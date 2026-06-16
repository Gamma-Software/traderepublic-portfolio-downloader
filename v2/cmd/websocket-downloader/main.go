package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dhojayev/traderepublic-portfolio-downloader/v2/internal"
	"github.com/dhojayev/traderepublic-portfolio-downloader/v2/internal/console"
	"github.com/dhojayev/traderepublic-portfolio-downloader/v2/internal/traderepublic/api"
	"github.com/dhojayev/traderepublic-portfolio-downloader/v2/internal/traderepublic/api/auth"
	"github.com/dhojayev/traderepublic-portfolio-downloader/v2/internal/traderepublic/api/restclient"
	"github.com/dhojayev/traderepublic-portfolio-downloader/v2/internal/traderepublic/api/websocketclient"
	"github.com/dhojayev/traderepublic-portfolio-downloader/v2/internal/waf"
	"github.com/joho/godotenv"
)

const (
	// Filepaths for saving responses.
	filepathTransactions = "./debug/transactions"

	// Filepaths for saving details.
	filepathDetails = "./debug/details"

	// Default timeout in seconds.
	defaultTimeoutSeconds = 60

	// Directory permissions.
	dirPermissions = 0700

	// File permissions.
	filePermissions = 0600
)

// TransactionItem represents a transaction item from the timeline.
type TransactionItem struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Action struct {
		Payload string `json:"payload"`
	} `json:"action"`
	Timestamp string `json:"timestamp"`
}

// TransactionsResponse represents the response from the timeline transactions API.
type TransactionsResponse struct {
	Items   []TransactionItem `json:"items"`
	Cursors struct {
		After string `json:"after"`
	} `json:"cursors"`
}

// Config holds the command line configuration.
type Config struct {
	debug       bool
	maxItems    int
	timeoutSecs int
	exportCSV   bool
	offline     bool
	authOnly    bool
	initAuth    bool
	last3Months bool
	fromDate    string
}

// parseFlags parses command line flags and returns a Config.
func parseFlags() Config {
	var config Config

	flag.BoolVar(&config.debug, "debug", false, "Enable debug logging")
	flag.IntVar(&config.maxItems, "max-items", 0, "Maximum number of items to process (0 = all)")
	flag.IntVar(&config.timeoutSecs, "timeout", defaultTimeoutSeconds, "Timeout in seconds for the entire operation")
	flag.BoolVar(&config.exportCSV, "export-csv", false, "Export transactions to CSV file")
	flag.BoolVar(&config.offline, "offline", false, "Use existing files in debug folder without downloading from API")
	flag.BoolVar(&config.authOnly, "auth-only", false, "Only perform authentication and generate token")
	flag.BoolVar(&config.initAuth, "init-auth", false, "Start login and exit (approve in the app, then run again)")
	flag.BoolVar(&config.last3Months, "last-3-months", false, "Only process transactions from the last 3 months")
	flag.StringVar(&config.fromDate, "from-date", "", "Only process transactions from this date (format: YYYY-MM-DD)")
	flag.Parse()

	return config
}

// setupLogger creates and configures a logger.
func setupLogger(debug bool) *slog.Logger {
	logOpts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if debug {
		logOpts.Level = slog.LevelDebug
	}

	return slog.New(slog.NewTextHandler(os.Stdout, logOpts))
}

// readCredentials returns the phone number and PIN from env vars, prompting interactively
// for whichever is missing.
func readCredentials() (string, string, error) {
	inputHandler := console.NewInputHandler()

	phoneNumber := os.Getenv("TR_PHONE_NUMBER")
	pin := os.Getenv("TR_PIN")

	var err error

	if phoneNumber == "" {
		if phoneNumber, err = inputHandler.GetPhoneNumber(); err != nil {
			return "", "", fmt.Errorf("failed to get phone number: %w", err)
		}
	}

	if pin == "" {
		if pin, err = inputHandler.GetPIN(); err != nil {
			return "", "", fmt.Errorf("failed to get PIN: %w", err)
		}
	}

	return phoneNumber, pin, nil
}

// ensureWAFToken makes sure a TR_WAF_TOKEN is available for the auth requests, generating
// one with a headless browser when the env var is empty.
func ensureWAFToken(logger *slog.Logger) {
	if os.Getenv("TR_WAF_TOKEN") != "" {
		return
	}

	token, err := waf.GetToken(context.Background(), logger, waf.DefaultTimeout)
	if err != nil {
		logger.Warn("Could not auto-generate AWS WAF token; set TR_WAF_TOKEN manually if login fails",
			"error", err)

		return
	}

	if err := os.Setenv("TR_WAF_TOKEN", token); err != nil {
		logger.Warn("Could not set TR_WAF_TOKEN", "error", err)
	}
}

// loginRateLimitWait returns the seconds to back off from a TOO_MANY_REQUESTS error, or 0.
func loginRateLimitWait(err error) int {
	if !strings.Contains(err.Error(), "TOO_MANY_REQUESTS") {
		return 0
	}

	matches := regexp.MustCompile(`nextAttemptInSeconds":(\d+)`).FindStringSubmatch(err.Error())
	if len(matches) > 1 {
		wait, _ := strconv.Atoi(matches[1])

		return wait
	}

	return 0
}

// startLogin performs the v2 login with simple rate-limit retry and returns the processId.
func startLogin(logger *slog.Logger, apiClient *api.Client, phone, pin string) (string, error) {
	const maxRetries = 3

	for attempt := 0; attempt < maxRetries; attempt++ {
		processID, err := apiClient.Login(restclient.APILoginRequest{PhoneNumber: phone, Pin: pin})
		if err == nil {
			return processID, nil
		}

		if wait := loginRateLimitWait(err); wait > 0 {
			logger.Info("Rate limited, waiting before retry", "seconds", wait)
			time.Sleep(time.Duration(wait) * time.Second)

			continue
		}

		return "", fmt.Errorf("failed to login: %w", err)
	}

	return "", fmt.Errorf("failed to login after %d retries", maxRetries)
}

// waitForApproval polls the login process until the user approves it in the mobile app,
// then returns the session/refresh tokens from the response cookies.
func waitForApproval(logger *slog.Logger, apiClient *api.Client, processID string) (auth.Token, error) {
	const (
		pollInterval = 2 * time.Second
		pollTimeout  = 2 * time.Minute
	)

	ctx, cancel := context.WithTimeout(context.Background(), pollTimeout)
	defer cancel()

	logger.Info("Login started — approve the web login in your Trade Republic mobile app")

	for {
		status, cookies, err := apiClient.PollLoginStatus(ctx, processID)
		if err != nil {
			return auth.Token{}, fmt.Errorf("failed to poll login status: %w", err)
		}

		switch status {
		case "CONFIRMED":
			token := auth.ExtractTokenFromCookies(cookies)
			if token.SessionToken() == "" {
				return auth.Token{}, errors.New("login confirmed but no session token returned")
			}

			return token, nil
		case "REJECTED", "CANCELED", "EXPIRED":
			return auth.Token{}, fmt.Errorf("login %s", status)
		}

		select {
		case <-ctx.Done():
			return auth.Token{}, fmt.Errorf("timed out waiting for app approval: %w", ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}

// authenticate performs the Trade Republic web login (app-approval flow) and returns a
// session token, reusing a cached token from the auth file when present.
func authenticate(logger *slog.Logger, config Config) (string, error) {
	credentials := auth.NewFileCredentialsService(internal.AuthTokenFilename)

	if config.authOnly {
		if err := os.Remove(internal.AuthTokenFilename); err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("failed to remove existing auth file: %w", err)
		}

		logger.Info("Removed existing auth file")
	}

	if err := credentials.Load(); err == nil && credentials.GetSessionToken() != "" {
		logger.Info("Using existing session token")

		return credentials.GetSessionToken(), nil
	}

	phoneNumber, pin, err := readCredentials()
	if err != nil {
		return "", err
	}

	ensureWAFToken(logger)

	apiClient, err := api.NewClient()
	if err != nil {
		return "", fmt.Errorf("failed to create API client: %w", err)
	}

	processID, err := startLogin(logger, apiClient, phoneNumber, pin)
	if err != nil {
		return "", err
	}

	if config.initAuth {
		logger.Info("Login initiated — approve it in your Trade Republic app, then run again")

		return "", nil
	}

	token, err := waitForApproval(logger, apiClient, processID)
	if err != nil {
		return "", err
	}

	if err := credentials.Store(token.SessionToken(), token.RefreshToken()); err != nil {
		logger.Warn("Failed to store tokens", "error", err)
	}

	logger.Info("Successfully authenticated")

	return token.SessionToken(), nil
}

// setupWebSocketClient creates and connects a WebSocket client.
func setupWebSocketClient(
	logger *slog.Logger,
	sessionToken string,
	timeoutSecs int,
) (*websocketclient.Client, context.Context, context.CancelFunc, error) {
	// Create WebSocket client
	wsClient, err := websocketclient.NewClient(
		websocketclient.WithLogger(logger),
		websocketclient.WithSessionToken(sessionToken),
	)
	if err != nil {
		logger.Error("Failed to create WebSocket client", "error", err)

		return nil, nil, nil, fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs)*time.Second)

	// Connect to WebSocket
	if err := wsClient.Connect(ctx); err != nil {
		cancel()
		logger.Error("Failed to connect to WebSocket", "error", err)

		return nil, nil, nil, fmt.Errorf("failed to connect to WebSocket: %w", err)
	}

	logger.Info("Connected to WebSocket, subscribing to timeline transactions...")

	return wsClient, ctx, cancel, nil
}

// startSessionRefresher periodically exchanges the refresh token for a fresh session
// token and pushes it into the WebSocket client, so runs longer than the ~5 min session
// lifetime (large portfolios) keep authenticating instead of dropping the tail.
func startSessionRefresher(
	ctx context.Context,
	logger *slog.Logger,
	apiClient *api.Client,
	wsClient *websocketclient.Client,
	credentials *auth.FileCredentialsService,
	refreshToken string,
) {
	if refreshToken == "" {
		logger.Warn("No refresh token available; session will not be refreshed")

		return
	}

	ticker := time.NewTicker(internal.SessionRefreshInterval * time.Second)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				newToken, err := apiClient.RefreshSession(refreshToken)
				if err != nil {
					logger.Warn("Failed to refresh session token", "error", err)

					continue
				}

				wsClient.SetSessionToken(newToken)

				if err := credentials.Store(newToken, refreshToken); err != nil {
					logger.Warn("Failed to persist refreshed token", "error", err)
				}

				logger.Info("Session token refreshed")
			}
		}
	}()
}

// fetchAllTransactions fetches all transactions with pagination.
func fetchAllTransactions(
	ctx context.Context,
	logger *slog.Logger,
	wsClient *websocketclient.Client,
) ([]TransactionItem, error) {
	var allTransactions []TransactionItem

	var cursor string

	var page int

	for {
		page++
		logger.Info("Fetching transactions page", "page", page)

		// Fetch page data
		transactionsData, err := fetchTransactionPage(ctx, logger, wsClient, cursor, page)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch transaction page: %w", err)
		}

		// Parse and process page data
		transactions, nextCursor, err := processTransactionPage(logger, transactionsData, page, allTransactions)
		if err != nil {
			return nil, fmt.Errorf("failed to process transaction page: %w", err)
		}

		// Add items to our collection
		allTransactions = append(allTransactions, transactions.Items...)
		logger.Info("Added transactions",
			"count", len(transactions.Items),
			"page", page,
			"total", len(allTransactions))

		// Check if we have more pages
		if nextCursor == "" {
			logger.Info("No more pages available")

			break
		}

		// Update cursor for next page
		cursor = nextCursor
		logger.Info("Next page cursor", "cursor", cursor)
	}

	if len(allTransactions) == 0 {
		logger.Error("No transactions found")

		return nil, errors.New("no transactions found")
	}

	// Save all transactions to a single file
	return saveAllTransactions(logger, allTransactions)
}

// fetchTransactionPage fetches a single page of transactions.
func fetchTransactionPage(
	ctx context.Context,
	logger *slog.Logger,
	wsClient *websocketclient.Client,
	cursor string,
	page int,
) ([]byte, error) {
	// Subscribe to timeline transactions with cursor if available
	var transactionsCh <-chan []byte

	var err error

	if cursor == "" {
		transactionsCh, err = wsClient.SubscribeToTimelineTransactions(ctx)
	} else {
		transactionsCh, err = wsClient.SubscribeToTimelineTransactionsWithCursor(ctx, cursor)
	}

	if err != nil {
		logger.Error("Failed to subscribe to timeline transactions", "error", err)

		return nil, fmt.Errorf("failed to subscribe to timeline transactions: %w", err)
	}

	// Wait for transactions data
	logger.Info("Waiting for timeline transactions data", "page", page)

	var transactionsData []byte

	select {
	case data := <-transactionsCh:
		transactionsData = data

		logger.Info("Received timeline transactions data", "page", page)
	case <-ctx.Done():
		logger.Error("Timeout waiting for timeline transactions", "error", ctx.Err())

		return nil, fmt.Errorf("timeout waiting for timeline transactions: %w", ctx.Err())
	}

	// Save transactions data for this page
	pageFilename := fmt.Sprintf("page_%d", page)
	if err := saveTransactionsData(pageFilename, transactionsData); err != nil {
		logger.Error("Failed to save transactions data", "error", err)

		return nil, fmt.Errorf("failed to save transactions data: %w", err)
	}

	return transactionsData, nil
}

// processTransactionPage processes a page of transaction data.
func processTransactionPage(
	logger *slog.Logger,
	transactionsData []byte,
	_ int, // page number, not used but kept for clarity
	_ []TransactionItem, // allTransactions, not used but kept for clarity
) (TransactionsResponse, string, error) {
	// Parse transactions data
	var transactions TransactionsResponse

	if err := json.Unmarshal(transactionsData, &transactions); err != nil {
		logger.Error("Failed to parse transactions data", "error", err)

		return TransactionsResponse{}, "", fmt.Errorf("failed to parse transactions data: %w", err)
	}

	return transactions, transactions.Cursors.After, nil
}

// saveAllTransactions saves all transactions to a single file.
func saveAllTransactions(logger *slog.Logger, allTransactions []TransactionItem) ([]TransactionItem, error) {
	allTransactionsData := map[string]interface{}{
		"items": allTransactions,
	}

	allTransactionsBytes, err := json.Marshal(allTransactionsData)
	if err != nil {
		logger.Error("Failed to marshal all transactions", "error", err)

		return nil, fmt.Errorf("failed to marshal all transactions: %w", err)
	}

	if err := saveTransactionsData("all_transactions", allTransactionsBytes); err != nil {
		logger.Error("Failed to save all transactions data", "error", err)

		return nil, fmt.Errorf("failed to save all transactions data: %w", err)
	}

	// Save as CSV
	if err := saveTransactionsAsCSV(logger, allTransactions); err != nil {
		logger.Error("Failed to save transactions as CSV", "error", err)
		return nil, fmt.Errorf("failed to save transactions as CSV: %w", err)
	}

	logger.Info("Found transactions", "count", len(allTransactions))

	return allTransactions, nil
}

// processTransactions processes the transactions and fetches details for each.
func processTransactions(
	ctx context.Context,
	logger *slog.Logger,
	wsClient *websocketclient.Client,
	allTransactions []TransactionItem,
	maxItems int,
) {
	// Determine how many items to process
	itemsToProcess := len(allTransactions)
	if maxItems > 0 && maxItems < itemsToProcess {
		itemsToProcess = maxItems
	}

	logger.Info("Processing transactions", "count", itemsToProcess)

	for i := 0; i < itemsToProcess; i++ {
		transaction := allTransactions[i]
		logger.Info("Processing transaction",
			"current", i+1,
			"total", itemsToProcess,
			"id", transaction.ID,
			"type", transaction.Type)

		// Get details for the transaction
		logger.Info("Fetching details for transaction", "payload", transaction.Action.Payload)

		detailsCh, err := wsClient.SubscribeToTimelineDetail(ctx, transaction.Action.Payload)
		if err != nil {
			logger.Error("Failed to subscribe to timeline detail", "error", err)

			continue
		}

		// Wait for details data
		logger.Debug("Waiting for timeline detail data")

		var detailsData []byte
		select {
		case data := <-detailsCh:
			detailsData = data

			logger.Debug("Received timeline detail data")
		case <-ctx.Done():
			logger.Error("Timeout waiting for timeline detail", "error", ctx.Err())

			continue
		}

		// Save details data
		if err := saveDetailsData(transaction.ID, detailsData); err != nil {
			logger.Error("Failed to save details data", "error", err)

			continue
		}

		logger.Info("Successfully processed transaction", "current", i+1, "total", itemsToProcess)
	}
}

// createDirectories creates the necessary directories for saving responses.
func createDirectories() error {
	dirs := []string{filepathTransactions, filepathDetails}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, dirPermissions); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// saveTransactionsData saves the transactions data to a file.
func saveTransactionsData(filename string, data []byte) error {
	// Save raw response data
	rawFilename := filepath.Join(filepathTransactions, filename+".raw.json")
	if err := os.WriteFile(rawFilename, data, filePermissions); err != nil {
		return fmt.Errorf("failed to write raw file: %w", err)
	}

	// Format the data for better readability.
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	formattedData, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON: %w", err)
	}

	// Save formatted data to file.
	formattedFilename := filepath.Join(filepathTransactions, filename+".json")
	if err := os.WriteFile(formattedFilename, formattedData, filePermissions); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Also save individual transaction files.
	var transactions TransactionsResponse
	if err := json.Unmarshal(data, &transactions); err != nil {
		return fmt.Errorf("failed to parse transactions: %w", err)
	}

	// Process each transaction
	for _, transaction := range transactions.Items {
		if err := saveIndividualTransaction(transaction); err != nil {
			return fmt.Errorf("failed to save individual transaction: %w", err)
		}
	}

	return nil
}

// saveIndividualTransaction saves a single transaction to a file.
func saveIndividualTransaction(transaction TransactionItem) error {
	// Create a map with just this transaction.
	singleTransaction := map[string]interface{}{
		"id":        transaction.ID,
		"type":      transaction.Type,
		"action":    transaction.Action,
		"timestamp": transaction.Timestamp,
	}

	// Format the data
	transactionData, err := json.MarshalIndent(singleTransaction, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format transaction JSON: %w", err)
	}

	// Save to file
	transFilename := filepath.Join(filepathTransactions, transaction.ID+".json")
	if err := os.WriteFile(transFilename, transactionData, filePermissions); err != nil {
		return fmt.Errorf("failed to write transaction file: %w", err)
	}

	// We don't save individual raw transaction data since they're part of the full response
	return nil
}

// saveDetailsData saves the details data to a file.
func saveDetailsData(id string, data []byte) error {
	// Save raw response data
	rawFilename := filepath.Join(filepathDetails, id+".raw.json")
	if err := os.WriteFile(rawFilename, data, filePermissions); err != nil {
		return fmt.Errorf("failed to write raw file: %w", err)
	}

	// Format the data for better readability
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}

	formattedData, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to format JSON: %w", err)
	}

	// Save formatted data to file
	formattedFilename := filepath.Join(filepathDetails, id+".json")
	if err := os.WriteFile(formattedFilename, formattedData, filePermissions); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// saveTransactionsAsCSV saves the transactions data to a CSV file.
func saveTransactionsAsCSV(logger *slog.Logger, transactions []TransactionItem) error {
	// Create CSV file
	csvFile := filepath.Join(filepathTransactions, "transactions.csv")
	f, err := os.Create(csvFile)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer f.Close()

	// Create CSV writer
	writer := csv.NewWriter(f)
	defer writer.Flush()

	// Write header
	header := []string{"ID", "Type", "Timestamp", "Payload"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write transactions
	for _, t := range transactions {
		record := []string{
			t.ID,
			t.Type,
			t.Timestamp,
			t.Action.Payload,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	logger.Info("Successfully saved transactions to CSV", "file", csvFile)
	return nil
}

// cleanAmount converts various amount formats to a consistent decimal string and returns the currency code.
// Trade Republic formats amounts in German locale (dot = thousands separator, comma = decimal),
// e.g. "1.234,56 €" -> "1234.56".
func cleanAmount(amount string) (string, string) {
	currencyMap := map[string]string{
		"€":   "EUR",
		"$":   "USD",
		"TND": "TND",
	}

	currencyCode := "EUR"

	// Strip currency symbols (and remember the code).
	for symbol, code := range currencyMap {
		if strings.Contains(amount, symbol) {
			currencyCode = code
			amount = strings.ReplaceAll(amount, symbol, "")
		}
	}

	// Strip currency codes that may appear as text (EUR/USD/TND).
	for _, code := range currencyMap {
		amount = strings.ReplaceAll(amount, code, "")
	}

	// Drop spaces (including non-breaking) and a leading plus sign.
	amount = strings.ReplaceAll(amount, " ", "")
	amount = strings.ReplaceAll(amount, " ", "")
	amount = strings.TrimPrefix(amount, "+")

	// Normalise separators. German style uses "." for thousands and "," for decimals.
	hasDot := strings.Contains(amount, ".")
	hasComma := strings.Contains(amount, ",")

	switch {
	case hasDot && hasComma:
		amount = strings.ReplaceAll(amount, ".", "")
		amount = strings.ReplaceAll(amount, ",", ".")
	case hasComma:
		amount = strings.ReplaceAll(amount, ",", ".")
	}

	return strings.TrimSpace(amount), currencyCode
}

// isNumericAmount reports whether a cleaned amount string parses as a number.
func isNumericAmount(cleaned string) bool {
	if cleaned == "" {
		return false
	}

	_, err := strconv.ParseFloat(cleaned, 64)

	return err == nil
}

// extractAmountFromTable scans a TR detail table for the first cell whose text is a monetary
// value, returning the cleaned amount, currency, and whether it is a credit (leading "+").
// This is more robust than reading a fixed row index, which varies by transaction layout.
func extractAmountFromTable(tableData []interface{}) (amount, currency string, isCredit, found bool) {
	for _, item := range tableData {
		itemMap, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		detailObj, ok := itemMap["detail"].(map[string]interface{})
		if !ok {
			continue
		}

		text, ok := detailObj["text"].(string)
		if !ok || text == "" {
			continue
		}

		// Only consider cells that actually carry a currency value.
		if !strings.ContainsAny(text, "€$") && !strings.Contains(text, "EUR") {
			continue
		}

		cleaned, code := cleanAmount(text)
		if !isNumericAmount(cleaned) {
			continue
		}

		return cleaned, code, strings.HasPrefix(strings.TrimSpace(text), "+"), true
	}

	return "", "", false, false
}

// formatDate converts various timestamp formats to a consistent format
func formatDate(timestamp string) string {
	// Try different time formats
	formats := []string{
		time.RFC3339,                    // 2025-06-01T14:03:13.686252+02:00
		"2006-01-02T15:04:05.000-0700", // 2025-06-01T09:38:50.444+0000
		"2006-01-02T15:04:05.000Z0700", // 2025-06-01T09:38:50.444+0000
	}

	for _, format := range formats {
		if t, err := time.Parse(format, timestamp); err == nil {
			// Format to desired output format
			return t.Format("2006-01-02T15:04:05")
		}
	}

	// If all parsing attempts fail, return original timestamp
	return timestamp
}

// exportTransactionsToCSV exports the transactions to a CSV file.
func exportTransactionsToCSV(logger *slog.Logger, transactions []TransactionItem) error {
	// Create CSV file in the debug root folder
	csvFile := filepath.Join("debug", "transactions.csv")
	f, err := os.Create(csvFile)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer f.Close()

	// Create CSV writer
	writer := csv.NewWriter(f)
	defer writer.Flush()

	// Write header
	headers := []string{
		"ID",
		"Date",
		"Type",
		"Description",
		"Amount Debit",
		"Amount Credit",
		"Currency",
	}
	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Process each transaction
	for _, transaction := range transactions {
		// Read the details file for this transaction
		detailsFile := filepath.Join(filepathDetails, transaction.ID+".json")
		data, err := os.ReadFile(detailsFile)
		if err != nil {
			logger.Warn("Failed to read details file", "id", transaction.ID, "error", err)
			continue
		}

		// Parse the details
		var detail struct {
			ID       string `json:"id"`
			Sections []struct {
				Type  string `json:"type"`
				Title string `json:"title"`
				Data  interface{} `json:"data"`
			} `json:"sections"`
		}

		if err := json.Unmarshal(data, &detail); err != nil {
			logger.Warn("Failed to parse details JSON", "id", transaction.ID, "error", err)
			continue
		}

		// Check if transaction is canceled
		isCanceled := false
		var cancelReason string

		// Check for canceled status in header section
		if len(detail.Sections) > 0 && detail.Sections[0].Type == "header" {
			if headerData, ok := detail.Sections[0].Data.(map[string]interface{}); ok {
				if status, ok := headerData["status"].(string); ok && status == "canceled" {
					isCanceled = true
				}
			}
		}

		// Check for CANCELED functional style in table sections
		for _, section := range detail.Sections {
			if section.Type == "table" {
				if tableData, ok := section.Data.([]interface{}); ok {
					for _, item := range tableData {
						if itemMap, ok := item.(map[string]interface{}); ok {
							if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
								if functionalStyle, ok := detailObj["functionalStyle"].(string); ok && functionalStyle == "CANCELED" {
									isCanceled = true
								}

								// Extract cancellation reason if available
								if title, ok := itemMap["title"].(string); ok && title == "Grund" {
									if text, ok := detailObj["text"].(string); ok {
										cancelReason = text
									}
								}
							}
						}
					}
				}
			}
		}

		// If transaction is canceled, log it and skip CSV export
		if isCanceled {
			logMsg := fmt.Sprintf("Skipping canceled transaction: %s", transaction.ID)
			if cancelReason != "" {
				logMsg += fmt.Sprintf(" (Reason: %s)", cancelReason)
			}
			if len(detail.Sections) > 0 {
				logMsg += fmt.Sprintf(" - %s", detail.Sections[0].Title)
			}
			logger.Info(logMsg)
			continue
		}

		// Check if transaction is a card verification
		isCardVerification := false

		// Check for card verification patterns in the title and sections
		if len(detail.Sections) > 0 {
			// Check main title for card verification keywords
			title := detail.Sections[0].Title
			if strings.Contains(title, "Karte wurde verifiziert") || strings.Contains(title, "Kartenprüfung") {
				isCardVerification = true
			}
		}

		// Check for card verification in banner section
		if !isCardVerification && len(detail.Sections) > 1 {
			for _, section := range detail.Sections {
				if section.Type == "banner" && section.Title == "Kartenprüfung" {
					isCardVerification = true
					break
				}
			}
		}

		// Check for card verification in table sections
		if !isCardVerification {
			for _, section := range detail.Sections {
				if section.Type == "table" {
					if tableData, ok := section.Data.([]interface{}); ok {
						for _, item := range tableData {
							if itemMap, ok := item.(map[string]interface{}); ok {
								if title, ok := itemMap["title"].(string); ok && title == "Kartenprüfung" {
									isCardVerification = true
									break
								}
							}
						}
					}
				}
				if isCardVerification {
					break
				}
			}
		}

		// If transaction is card verification, log it and skip CSV export
		if isCardVerification {
			logMsg := fmt.Sprintf("Skipping card verification transaction: %s", transaction.ID)
			if len(detail.Sections) > 0 {
				logMsg += fmt.Sprintf(" - %s", detail.Sections[0].Title)
			}
			logger.Info(logMsg)
			continue
		}

		// Check if transaction is a card purchase
		isCardPurchase := false

		// Check for card purchase patterns in documents section
		for _, section := range detail.Sections {
			if section.Type == "documents" {
				if documentsData, ok := section.Data.([]interface{}); ok {
					for _, doc := range documentsData {
						if docMap, ok := doc.(map[string]interface{}); ok {
							if title, ok := docMap["title"].(string); ok {
								if strings.Contains(title, "Trade Republic Karte") || strings.Contains(title, "Bestellung Trade Republic Karte") {
									isCardPurchase = true
									break
								}
							}
						}
					}
				}
			}
			if isCardPurchase {
				break
			}
		}

		// If transaction is card purchase, log it and skip CSV export
		if isCardPurchase {
			logMsg := fmt.Sprintf("Skipping card purchase transaction: %s", transaction.ID)
			if len(detail.Sections) > 0 {
				logMsg += fmt.Sprintf(" - %s", detail.Sections[0].Title)
			}
			logger.Info(logMsg)
			continue
		}

		// Extract data from sections
		record := make(map[string]string)
		record["ID"] = detail.ID
		record["Type"] = "transaction" // Set default type to "transaction"
		record["Amount Debit"] = "0"
		record["Amount Credit"] = "0"
		record["Currency"] = "EUR" // Default currency

		// Get timestamp from first section (header)
		if len(detail.Sections) > 0 && detail.Sections[0].Type == "header" {
			if headerData, ok := detail.Sections[0].Data.(map[string]interface{}); ok {
				if timestamp, ok := headerData["timestamp"].(string); ok {
					record["Date"] = formatDate(timestamp)
				}
			}
		}

		// Check if it's an investment transaction
		isInvestment := false
		if strings.Contains(detail.Sections[0].Title, "investiert") {
			isInvestment = true

			// Check if it's a round-up transaction
			isRoundUp := false
			var assetName string

			if len(detail.Sections) > 1 && detail.Sections[1].Type == "table" {
				if tableData, ok := detail.Sections[1].Data.([]interface{}); ok {
					for _, item := range tableData {
						if itemMap, ok := item.(map[string]interface{}); ok {
							if title, ok := itemMap["title"].(string); ok {
								if title == "Round up" {
									isRoundUp = true
									record["Type"] = "round up"
								} else if title == "Asset" {
									if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
										if text, ok := detailObj["text"].(string); ok {
											assetName = text
										}
									}
								} else if title == "Gesamt" {
									if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
										if text, ok := detailObj["text"].(string); ok {
											amount, currency := cleanAmount(text)
											record["Amount Debit"] = amount
											record["Currency"] = currency
										}
									}
								}
							}
						}
					}
				}
			}

			if isRoundUp {
				// Set description for round-up
				if assetName != "" {
					record["Description"] = fmt.Sprintf("Round up investment in %s", assetName)
				} else {
					record["Description"] = "Round up investment"
				}
			} else {
				// Continue with existing investment processing logic
				// Check if it's a trading execution (has Orderart field)
				isTrading := false
				isSparplan := false
				var orderType, shares, stockPrice string

				if len(detail.Sections) > 1 && detail.Sections[1].Type == "table" {
					if tableData, ok := detail.Sections[1].Data.([]interface{}); ok {
						for _, item := range tableData {
							if itemMap, ok := item.(map[string]interface{}); ok {
								if title, ok := itemMap["title"].(string); ok {
									if title == "Orderart" {
										if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
											if text, ok := detailObj["text"].(string); ok {
												orderType = text
												if text == "Sparplan" {
													isSparplan = true
													record["Type"] = "savings plan"
												} else {
													isTrading = true
												}
											}
										}
									} else if title == "Asset" {
										if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
											if text, ok := detailObj["text"].(string); ok {
												assetName = text
											}
										}
									}
								}
							}
						}
					}
				}

				if isSparplan {
					// Handle Sparplan (savings plan) transactions
					record["Description"] = fmt.Sprintf("Savings plan investment in %s", assetName)

					// Get amount from the "Transaktion" section (usually section 3)
					for _, section := range detail.Sections {
						if section.Title == "Transaktion" && section.Type == "table" {
							if tableData, ok := section.Data.([]interface{}); ok {
								for _, item := range tableData {
									if itemMap, ok := item.(map[string]interface{}); ok {
										if title, ok := itemMap["title"].(string); ok && title == "Gesamt" {
											if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
												if text, ok := detailObj["text"].(string); ok {
													amount, currency := cleanAmount(text)
													record["Amount Debit"] = amount
													record["Currency"] = currency
												}
											}
										}
									}
								}
							}
						}
					}
				} else if isTrading {
					// Get trading details from section 2
					if len(detail.Sections) > 2 && detail.Sections[2].Type == "table" {
						if tableData, ok := detail.Sections[2].Data.([]interface{}); ok {
							for _, item := range tableData {
								if itemMap, ok := item.(map[string]interface{}); ok {
									if title, ok := itemMap["title"].(string); ok {
										if title == "Anteile" {
											if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
												if text, ok := detailObj["text"].(string); ok {
													shares = text
												}
											}
										} else if title == "Aktienkurs" {
											if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
												if text, ok := detailObj["text"].(string); ok {
													stockPrice = text
												}
											}
										} else if title == "Gesamt" {
											if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
												if text, ok := detailObj["text"].(string); ok {
													amount, currency := cleanAmount(text)
													if orderType == "Kauf" {
														record["Type"] = "stock purchase"
														record["Amount Debit"] = amount
													} else if orderType == "Verkauf" {
														record["Type"] = "stock sale"
														record["Amount Credit"] = amount
													}
													record["Currency"] = currency
												}
											}
										}
									}
								}
							}
						}
					}

					// Build description with trading details
					description := fmt.Sprintf("%s - %s shares at %s per share", assetName, shares, stockPrice)
					record["Description"] = description
				} else {
					// Keep existing investment logic for non-trading investments
					record["Type"] = "investment"
					// Get description from section data
					if len(detail.Sections) > 1 && detail.Sections[1].Type == "table" {
						if tableData, ok := detail.Sections[1].Data.([]interface{}); ok {
							if len(tableData) > 0 {
								if item, ok := tableData[0].(map[string]interface{}); ok {
									if detailObj, ok := item["detail"].(map[string]interface{}); ok {
										if text, ok := detailObj["text"].(string); ok {
											record["Description"] = text
										}
									}
								}
							}
						}
					}

					// Extract amount from title
					re := regexp.MustCompile(`([0-9,.]+)\s*€`)
					matches := re.FindStringSubmatch(detail.Sections[0].Title)
					if len(matches) > 1 {
						amount, currency := cleanAmount(matches[1] + " €")
						record["Amount Debit"] = amount
						record["Currency"] = currency
					}
				}
			}
		}

		// Check if it's a transfer (has IBAN field)
		isTransfer := false
		if !isInvestment && len(detail.Sections) > 1 && detail.Sections[1].Type == "table" {
			if tableData, ok := detail.Sections[1].Data.([]interface{}); ok {
				for _, item := range tableData {
					if itemMap, ok := item.(map[string]interface{}); ok {
						if title, ok := itemMap["title"].(string); ok {
							if title == "IBAN" {
								isTransfer = true
								record["Type"] = "transfer"

								// Get sender name from sections[1].data[1].detail.text
								var senderName string
								if len(tableData) > 1 {
									if item1, ok := tableData[1].(map[string]interface{}); ok {
										if detail1, ok := item1["detail"].(map[string]interface{}); ok {
											if text, ok := detail1["text"].(string); ok {
												senderName = text
											}
										}
									}
								}

								// Get IBAN from sections[1].data[2].detail.text
								var iban string
								if len(tableData) > 2 {
									if item2, ok := tableData[2].(map[string]interface{}); ok {
										if detail2, ok := item2["detail"].(map[string]interface{}); ok {
											if text, ok := detail2["text"].(string); ok {
												iban = text
											}
										}
									}
								}

								// Combine sender name and IBAN for description
								record["Description"] = fmt.Sprintf("Transfer from %s %s", senderName, iban)

								// Get amount from sections[2].data[1].detail.action.payload.contextParams.amount
								if len(detail.Sections) > 2 && detail.Sections[2].Type == "table" {
									if tableData2, ok := detail.Sections[2].Data.([]interface{}); ok {
										if len(tableData2) > 0 {
											if item2, ok := tableData2[0].(map[string]interface{}); ok {
												if detail2, ok := item2["detail"].(map[string]interface{}); ok {
													if action, ok := detail2["action"].(map[string]interface{}); ok {
														if payload, ok := action["payload"].(map[string]interface{}); ok {
															if contextParams, ok := payload["contextParams"].(map[string]interface{}); ok {
																if amount, ok := contextParams["amount"].(string); ok {
																	// For transfers, if the title contains "erhalten" (received), it's a credit
																	if strings.Contains(detail.Sections[0].Title, "erhalten") {
																		record["Amount Credit"] = amount
																	} else {
																		record["Amount Debit"] = amount
																	}
																	record["Currency"] = "EUR" // Transfers are always in EUR
																}
															}
														}
													}
												}
											}
										}
									}
								}
								break
							}
						}
					}
				}
			}
		}

		// Check if it's a top-up (Apple Pay, etc.)
		isTopUp := false
		if !isInvestment && !isTransfer && len(detail.Sections) > 1 && detail.Sections[1].Type == "table" {
			if tableData, ok := detail.Sections[1].Data.([]interface{}); ok {
				for _, item := range tableData {
					if itemMap, ok := item.(map[string]interface{}); ok {
						if title, ok := itemMap["title"].(string); ok {
							if title == "Zahlung" {
								if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
									if text, ok := detailObj["text"].(string); ok {
										if text == "Apple Pay" {
											isTopUp = true
											record["Type"] = "top up"
											record["Description"] = "apple top up"

											// Get amount from sections[2].data[1].detail.text (Betrag)
											if len(detail.Sections) > 2 && detail.Sections[2].Type == "table" {
												if tableData2, ok := detail.Sections[2].Data.([]interface{}); ok {
													if len(tableData2) > 1 {
														if item2, ok := tableData2[1].(map[string]interface{}); ok {
															if detail2, ok := item2["detail"].(map[string]interface{}); ok {
																if text2, ok := detail2["text"].(string); ok {
																	amount, currency := cleanAmount(text2)
																	record["Amount Credit"] = amount
																	record["Currency"] = currency
																}
															}
														}
													}
												}
											}
											break
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Check if it's a dividend transaction
		isDividend := false
		if !isInvestment && !isTransfer && !isTopUp && len(detail.Sections) > 1 && detail.Sections[1].Type == "table" {
			if tableData, ok := detail.Sections[1].Data.([]interface{}); ok {
				for _, item := range tableData {
					if itemMap, ok := item.(map[string]interface{}); ok {
						if title, ok := itemMap["title"].(string); ok {
							// Check for "Bardividende" in "Event" field
							if title == "Event" {
								if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
									if text, ok := detailObj["text"].(string); ok {
										if text == "Bardividende" {
											isDividend = true
											record["Type"] = "dividend"

											// Get security name from Wertpapier field
											for _, item2 := range tableData {
												if itemMap2, ok := item2.(map[string]interface{}); ok {
													if title2, ok := itemMap2["title"].(string); ok {
														if title2 == "Wertpapier" {
															if detailObj2, ok := itemMap2["detail"].(map[string]interface{}); ok {
																if text2, ok := detailObj2["text"].(string); ok {
																	record["Description"] = text2
																	break
																}
															}
														}
													}
												}
											}

											// Get amount from sections[2].data[3].detail.text (Gesamt)
											if len(detail.Sections) > 2 && detail.Sections[2].Type == "table" {
												if tableData2, ok := detail.Sections[2].Data.([]interface{}); ok {
													if len(tableData2) > 3 {
														if item2, ok := tableData2[3].(map[string]interface{}); ok {
															if detail2, ok := item2["detail"].(map[string]interface{}); ok {
																if text2, ok := detail2["text"].(string); ok {
																	amount, currency := cleanAmount(text2)
																	record["Amount Credit"] = amount
																	record["Currency"] = currency
																}
															}
														}
													}
												}
											}
											break
										}
									}
								}
							// Check for "Dividende" in "Ereignis" field (German for Event)
							} else if title == "Ereignis" {
								if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
									if text, ok := detailObj["text"].(string); ok {
										if text == "Dividende" {
											isDividend = true
											record["Type"] = "dividend"

											// Get asset name from Asset field
											for _, item2 := range tableData {
												if itemMap2, ok := item2.(map[string]interface{}); ok {
													if title2, ok := itemMap2["title"].(string); ok {
														if title2 == "Asset" {
															if detailObj2, ok := itemMap2["detail"].(map[string]interface{}); ok {
																if text2, ok := detailObj2["text"].(string); ok {
																	record["Description"] = text2
																	break
																}
															}
														}
													}
												}
											}

											// Get amount from sections[2].data[3].detail.text (Gesamt)
											if len(detail.Sections) > 2 && detail.Sections[2].Type == "table" {
												if tableData2, ok := detail.Sections[2].Data.([]interface{}); ok {
													if len(tableData2) > 3 {
														if item2, ok := tableData2[3].(map[string]interface{}); ok {
															if detail2, ok := item2["detail"].(map[string]interface{}); ok {
																if text2, ok := detail2["text"].(string); ok {
																	amount, currency := cleanAmount(text2)
																	record["Amount Credit"] = amount
																	record["Currency"] = currency
																}
															}
														}
													}
												}
											}
											break
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Check if it's a savings transaction (Sparplan or Saveback)
		isSavings := false
		if !isInvestment && !isTransfer && !isTopUp && !isDividend && len(detail.Sections) > 1 && detail.Sections[1].Type == "table" {
			if tableData, ok := detail.Sections[1].Data.([]interface{}); ok {
				if len(tableData) > 0 {
					if item, ok := tableData[0].(map[string]interface{}); ok {
						if title, ok := item["title"].(string); ok {
							if title == "Saveback" {
								isSavings = true
								record["Type"] = "saveback"
								// Get description from sections[1].data[1].detail.text
								if len(tableData) > 1 {
									if item2, ok := tableData[1].(map[string]interface{}); ok {
										if detail2, ok := item2["detail"].(map[string]interface{}); ok {
											if text, ok := detail2["text"].(string); ok {
												record["Description"] = text
											}
										}
									}
								}
								// Get amount from sections[1].data[4].detail.text
								if len(tableData) > 4 {
									if item2, ok := tableData[4].(map[string]interface{}); ok {
										if detail2, ok := item2["detail"].(map[string]interface{}); ok {
											if text, ok := detail2["text"].(string); ok {
												amount, currency := cleanAmount(text)
												record["Amount Debit"] = amount
												record["Currency"] = currency
											}
										}
									}
								}
							} else if title == "Sparplan" {
								isSavings = true
								record["Type"] = "savings"
								// Get description from sections[1].data[2].detail.text
								if len(detail.Sections) > 1 && detail.Sections[1].Type == "table" {
									if tableData2, ok := detail.Sections[1].Data.([]interface{}); ok {
										if len(tableData2) > 2 {
											if item2, ok := tableData2[2].(map[string]interface{}); ok {
												if detail2, ok := item2["detail"].(map[string]interface{}); ok {
													if title2, ok := detail2["text"].(string); ok {
														record["Description"] = title2
													}
												}
											}
										}
									}
								}

								// Get amount from sections[2].data[0].detail.amount
								if len(detail.Sections) > 2 && detail.Sections[2].Type == "table" {
									if tableData2, ok := detail.Sections[2].Data.([]interface{}); ok {
										if len(tableData2) > 0 {
											if item2, ok := tableData2[0].(map[string]interface{}); ok {
												if detail2, ok := item2["detail"].(map[string]interface{}); ok {
													if amount, ok := detail2["amount"].(string); ok {
														cleanedAmount, currency := cleanAmount(amount)
														record["Amount Debit"] = cleanedAmount
														record["Currency"] = currency
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		// Check if it's an interest payout
		isInterestPayout := false
		if !isInvestment && !isSavings && !isTransfer && !isTopUp && !isDividend {
			// Method 1: Check for interest icon in header
			if len(detail.Sections) > 0 && detail.Sections[0].Type == "header" {
				if headerData, ok := detail.Sections[0].Data.(map[string]interface{}); ok {
					if icon, ok := headerData["icon"].(string); ok {
						if strings.Contains(icon, "timeline_interest") {
							isInterestPayout = true
							record["Type"] = "interest"
							record["Description"] = "Interest payout"
						}
					}
				}
			}

			// Method 2: Check for "Jährliche Rate" in table sections (fallback)
			if !isInterestPayout && len(detail.Sections) > 1 {
				for _, section := range detail.Sections {
					if section.Type == "table" {
						if tableData, ok := section.Data.([]interface{}); ok {
							for _, item := range tableData {
								if itemMap, ok := item.(map[string]interface{}); ok {
									if title, ok := itemMap["title"].(string); ok {
										if title == "Jährliche Rate" {
											isInterestPayout = true
											record["Type"] = "interest"
											record["Description"] = "Interest payout"
											break
										}
									}
								}
							}
						}
					}
					if isInterestPayout {
						break
					}
				}
			}
		}

		if isInterestPayout {
			// For interest payouts, search for amount in multiple ways
			amountFound := false

			// Method 1: Extract amount from title (e.g., "Du hast 80,96 EUR erhalten")
			if !amountFound && len(detail.Sections) > 0 {
				title := detail.Sections[0].Title
				re := regexp.MustCompile(`([0-9,.]+)\s*(€|EUR)\s+erhalten`)
				matches := re.FindStringSubmatch(title)
				if len(matches) > 1 {
					amount, currency := cleanAmount(matches[1] + " " + matches[2])
					record["Amount Credit"] = amount
					record["Currency"] = currency
					amountFound = true
				}
			}

			// Method 2: Look for "Gesamt" in any table section
			if !amountFound {
				for _, section := range detail.Sections {
					if section.Type == "table" {
						if tableData, ok := section.Data.([]interface{}); ok {
							for _, item := range tableData {
								if itemMap, ok := item.(map[string]interface{}); ok {
									if title, ok := itemMap["title"].(string); ok {
										if title == "Gesamt" {
											if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
												if text, ok := detailObj["text"].(string); ok {
													amount, currency := cleanAmount(text)
													record["Amount Credit"] = amount
													record["Currency"] = currency
													amountFound = true
													break
												}
											}
										}
									}
								}
							}
						}
					}
					if amountFound {
						break
					}
				}
			}
		}

		// Check if it's a PEA activation
		isPEAActivation := false
		if !isInvestment && !isSavings && !isTransfer && !isTopUp && !isDividend && !isInterestPayout {
			// Look for "PEA-Aktivierung" in table sections
			for _, section := range detail.Sections {
				if section.Type == "table" {
					if tableData, ok := section.Data.([]interface{}); ok {
						for _, item := range tableData {
							if itemMap, ok := item.(map[string]interface{}); ok {
								if title, ok := itemMap["title"].(string); ok {
									if title == "Ereignistyp" {
										if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
											if text, ok := detailObj["text"].(string); ok {
												if text == "PEA-Aktivierung" {
													isPEAActivation = true
													record["Type"] = "pea activation"
													record["Description"] = "PEA activation bonus"

													// Extract amount from title (e.g., "Du hast 1.00 € erhalten")
													if len(detail.Sections) > 0 {
														title := detail.Sections[0].Title
														re := regexp.MustCompile(`([0-9,.]+)\s*(€|EUR)\s+erhalten`)
														matches := re.FindStringSubmatch(title)
														if len(matches) > 1 {
															amount, currency := cleanAmount(matches[1] + " " + matches[2])
															record["Amount Credit"] = amount
															record["Currency"] = currency
														}
													}
													break
												}
											}
										}
									}
								}
							}
						}
					}
				}
				if isPEAActivation {
					break
				}
			}
		}

		// Check if it's a brokerage transaction
		isBrokerage := false
		if !isInvestment && !isSavings && !isTransfer && !isTopUp && !isDividend && !isInterestPayout && !isPEAActivation {
			// Check for brokerage in first table section
			if len(detail.Sections) > 1 && detail.Sections[1].Type == "table" {
				if tableData, ok := detail.Sections[1].Data.([]interface{}); ok {
					for _, item := range tableData {
						if itemMap, ok := item.(map[string]interface{}); ok {
							if title, ok := itemMap["title"].(string); ok {
								if title == "Portfolio" {
									if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
										if text, ok := detailObj["text"].(string); ok {
											if text == "Brokerage" {
												isBrokerage = true
												record["Type"] = "brokerage"
												break
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}

		if isBrokerage {
			// Get asset name and order type from first table section
			var assetName, orderType string
			if len(detail.Sections) > 1 && detail.Sections[1].Type == "table" {
				if tableData, ok := detail.Sections[1].Data.([]interface{}); ok {
					for _, item := range tableData {
						if itemMap, ok := item.(map[string]interface{}); ok {
							if title, ok := itemMap["title"].(string); ok {
								if title == "Asset" {
									if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
										if text, ok := detailObj["text"].(string); ok {
											assetName = text
										}
									}
								} else if title == "Orderart" {
									if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
										if text, ok := detailObj["text"].(string); ok {
											orderType = text
											// Set type based on order type
											if strings.Contains(text, "Kauf") {
												record["Type"] = "stock purchase"
											} else if strings.Contains(text, "Verkauf") {
												record["Type"] = "stock sale"
											}
										}
									}
								}
							}
						}
					}
				}
			}

			// Get shares and price from transaction section
			var shares, price string
			if len(detail.Sections) > 2 && detail.Sections[2].Type == "table" {
				if tableData, ok := detail.Sections[2].Data.([]interface{}); ok {
					for _, item := range tableData {
						if itemMap, ok := item.(map[string]interface{}); ok {
							if title, ok := itemMap["title"].(string); ok {
								if title == "Anteile" {
									if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
										if text, ok := detailObj["text"].(string); ok {
											shares = text
										}
									}
								} else if title == "Aktienkurs" {
									if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
										if text, ok := detailObj["text"].(string); ok {
											price = text
										}
									}
								} else if title == "Gesamt" {
									if detailObj, ok := itemMap["detail"].(map[string]interface{}); ok {
										if text, ok := detailObj["text"].(string); ok {
											amount, currency := cleanAmount(text)
											if strings.Contains(orderType, "Kauf") {
												record["Amount Debit"] = amount
											} else if strings.Contains(orderType, "Verkauf") {
												record["Amount Credit"] = amount
											}
											record["Currency"] = currency
										}
									}
								}
							}
						}
					}
				}
			}

			// Build description
			record["Description"] = fmt.Sprintf("%s - %s shares at %s per share", assetName, shares, price)
		}

		if !isInvestment && !isSavings && !isTransfer && !isTopUp && !isDividend && !isInterestPayout && !isPEAActivation && !isBrokerage {
			// For regular transactions, get description and amount from second section.
			if len(detail.Sections) > 1 && detail.Sections[1].Type == "table" {
				if tableData, ok := detail.Sections[1].Data.([]interface{}); ok {
					// Description: index 2 holds it, but only if it is not itself a currency value.
					if len(tableData) > 2 {
						if item, ok := tableData[2].(map[string]interface{}); ok {
							if d, ok := item["detail"].(map[string]interface{}); ok {
								if text, ok := d["text"].(string); ok {
									cleaned, _ := cleanAmount(text)
									if !isNumericAmount(cleaned) {
										record["Description"] = text
									}
								}
							}
						}
					}

					// Amount: scan for the monetary cell instead of trusting a fixed index,
					// which previously let asset names leak into the amount columns.
					if amount, currency, isCredit, found := extractAmountFromTable(tableData); found {
						if isCredit {
							record["Amount Credit"] = amount
						} else {
							record["Amount Debit"] = amount
						}
						record["Currency"] = currency
					}
				}
			}
		}

		// Remove commas from the Description field
		if desc, ok := record["Description"]; ok {
			record["Description"] = strings.ReplaceAll(desc, ",", ".")
		}

		// Date fallback: some details (e.g. round-ups) carry no header timestamp;
		// use the timeline item's timestamp instead of emitting N/A.
		if record["Date"] == "" && transaction.Timestamp != "" {
			record["Date"] = formatDate(transaction.Timestamp)
		}

		// Defensive net: never let a non-numeric value land in a numeric column.
		for _, col := range []string{"Amount Debit", "Amount Credit"} {
			if !isNumericAmount(record[col]) {
				if record[col] != "" && record[col] != "0" {
					logger.Warn("Discarded non-numeric amount",
						"id", transaction.ID, "column", col, "value", record[col])
				}

				record[col] = "0"
			}
		}

		// Write record to CSV
		var row []string
		for _, header := range headers {
			value := record[header]
			if value == "" {
				value = "N/A" // Use N/A for empty values
			}
			row = append(row, value)
		}
		if err := writer.Write(row); err != nil {
			logger.Warn("Failed to write CSV record", "id", transaction.ID, "error", err)
			continue
		}

		// If Saveback, add an additional credit line
		if record["Type"] == "saveback" && record["Amount Debit"] != "0" {
			creditRow := make([]string, len(headers))
			for i, header := range headers {
				switch header {
				case "ID":
					creditRow[i] = record["ID"]
				case "Date":
					creditRow[i] = record["Date"]
				case "Type":
					creditRow[i] = "saveback"
				case "Description":
					creditRow[i] = "Your Saveback payment"
				case "Amount Debit":
					creditRow[i] = "0"
				case "Amount Credit":
					creditRow[i] = record["Amount Debit"]
				case "Currency":
					creditRow[i] = record["Currency"]
				default:
					creditRow[i] = "N/A"
				}
			}
			if err := writer.Write(creditRow); err != nil {
				logger.Warn("Failed to write Saveback credit CSV record", "id", transaction.ID, "error", err)
				continue
			}
		}

		logger.Debug("Wrote transaction to CSV", "id", transaction.ID)
	}

	logger.Info("Successfully exported transactions to CSV", "file", csvFile, "count", len(transactions))
	return nil
}

// loadTransactionsFromDebug loads transactions from existing files in the debug folder
func loadTransactionsFromDebug(logger *slog.Logger) ([]TransactionItem, error) {
	var transactions []TransactionItem

	// Read all transaction files from debug/transactions directory
	files, err := filepath.Glob(filepath.Join(filepathTransactions, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to read transaction files: %w", err)
	}

	for _, file := range files {
		// Skip raw files and all_transactions.json
		if strings.HasSuffix(file, ".raw.json") || strings.Contains(file, "all_transactions") {
			continue
		}

		// Read the file
		data, err := os.ReadFile(file)
		if err != nil {
			logger.Warn("Failed to read transaction file", "file", file, "error", err)
			continue
		}

		// Parse single transaction
		var transaction struct {
			ID        string `json:"id"`
			Type      string `json:"type"`
			Timestamp string `json:"timestamp"`
		}

		if err := json.Unmarshal(data, &transaction); err != nil {
			logger.Warn("Failed to parse transaction file", "file", file, "error", err)
			continue
		}

		// Add to transactions list
		transactions = append(transactions, TransactionItem{
			ID:        transaction.ID,
			Type:      transaction.Type,
			Timestamp: transaction.Timestamp,
		})
	}

	logger.Info("Loaded transactions from debug folder", "count", len(transactions))
	return transactions, nil
}

// filterTransactionsByDate filters transactions to only include those from the last 3 months
func filterTransactionsByDate(transactions []TransactionItem, config Config) []TransactionItem {
	if !config.last3Months && config.fromDate == "" {
		return transactions
	}

	var filtered []TransactionItem
	var cutoffTime time.Time

	if config.last3Months {
		cutoffTime = time.Now().AddDate(0, -3, 0)
	} else if config.fromDate != "" {
		var err error
		cutoffTime, err = time.Parse("2006-01-02", config.fromDate)
		if err != nil {
			// If date parsing fails, return all transactions
			return transactions
		}
		// Set cutoff time to start of the day
		cutoffTime = time.Date(cutoffTime.Year(), cutoffTime.Month(), cutoffTime.Day(), 0, 0, 0, 0, time.UTC)
	}

	logger := slog.Default()
	logger.Info("Filtering transactions by date",
		"cutoff_date", cutoffTime.Format("2006-01-02 15:04:05"),
		"total_transactions", len(transactions))

	// Define all possible timestamp formats
	formats := []string{
		time.RFC3339,                    // 2025-06-01T14:03:13.686252+02:00
		"2006-01-02T15:04:05.000-0700", // 2025-06-01T09:38:50.444+0000
		"2006-01-02T15:04:05.000Z0700", // 2025-06-01T09:38:50.444+0000
		"2006-01-02T15:04:05-0700",     // 2025-06-01T09:38:50+0000
		"2006-01-02T15:04:05Z0700",     // 2025-06-01T09:38:50+0000
	}

	for _, t := range transactions {
		var transactionTime time.Time
		var parseErr error

		// Try each format until we find one that works
		for _, format := range formats {
			transactionTime, parseErr = time.Parse(format, t.Timestamp)
			if parseErr == nil {
				break
			}
		}

		if parseErr != nil {
			logger.Warn("Failed to parse transaction timestamp",
				"transaction_id", t.ID,
				"timestamp", t.Timestamp,
				"error", parseErr)
			// If timestamp parsing fails, include the transaction
			filtered = append(filtered, t)
			continue
		}

		// Convert transaction time to UTC for comparison
		transactionTime = transactionTime.UTC()

		if transactionTime.After(cutoffTime) || transactionTime.Equal(cutoffTime) {
			filtered = append(filtered, t)
		} else {
			logger.Debug("Filtered out transaction",
				"transaction_id", t.ID,
				"transaction_date", transactionTime.Format("2006-01-02 15:04:05"),
				"cutoff_date", cutoffTime.Format("2006-01-02 15:04:05"))
		}
	}

	logger.Info("Date filtering complete",
		"original_count", len(transactions),
		"filtered_count", len(filtered))

	return filtered
}

func main() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		// Ignore error if .env file doesn't exist
	}

	// Parse command line flags
	config := parseFlags()

	// Setup logger
	logger := setupLogger(config.debug)

	// Create required directories
	if err := createDirectories(); err != nil {
		logger.Error("Failed to create directories", "error", err)
		os.Exit(1)
	}

	// If offline mode is enabled, load transactions from debug folder
	if config.offline {
		transactions, err := loadTransactionsFromDebug(logger)
		if err != nil {
			logger.Error("Failed to load transactions from debug folder", "error", err)
			os.Exit(1)
		}

		// Filter transactions by date if needed
		transactions = filterTransactionsByDate(transactions, config)

		// Export to CSV if requested
		if config.exportCSV {
			if err := exportTransactionsToCSV(logger, transactions); err != nil {
				logger.Error("Failed to export transactions to CSV", "error", err)
				os.Exit(1)
			}
		}

		return
	}

	// Authenticate and get session token
	sessionToken, err := authenticate(logger, config)
	if err != nil {
		logger.Error("Failed to authenticate", "error", err)
		os.Exit(1)
	}

	// If authOnly or initAuth is true, exit here
	if config.authOnly || config.initAuth {
		return
	}

	// Setup WebSocket client
	wsClient, ctx, cancel, err := setupWebSocketClient(logger, sessionToken, config.timeoutSecs)
	if err != nil {
		logger.Error("Failed to setup WebSocket client", "error", err)
		os.Exit(1)
	}
	defer cancel()

	// Start background session refresher to keep long runs authenticated.
	credentials := auth.NewFileCredentialsService(internal.AuthTokenFilename)
	_ = credentials.Load()

	if apiClient, apiErr := api.NewClient(); apiErr != nil {
		logger.Warn("Could not create API client for session refresher", "error", apiErr)
	} else {
		startSessionRefresher(ctx, logger, apiClient, wsClient, credentials, credentials.GetRefreshToken())
	}

	// Fetch all transactions
	transactions, err := fetchAllTransactions(ctx, logger, wsClient)
	if err != nil {
		logger.Error("Failed to fetch transactions", "error", err)
		os.Exit(1)
	}

	// Filter transactions by date if needed
	transactions = filterTransactionsByDate(transactions, config)

	// Process transactions
	processTransactions(ctx, logger, wsClient, transactions, config.maxItems)

	// Export to CSV if requested
	if config.exportCSV {
		if err := exportTransactionsToCSV(logger, transactions); err != nil {
			logger.Error("Failed to export transactions to CSV", "error", err)
			os.Exit(1)
		}
	}
}
