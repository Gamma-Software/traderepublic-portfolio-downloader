package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/dhojayev/traderepublic-portfolio-downloader/v2/internal"
	"github.com/dhojayev/traderepublic-portfolio-downloader/v2/internal/traderepublic/api/restclient"
)

const (
	// HTTP status code threshold for error responses.
	statusCodeError = http.StatusBadRequest
)

// Client is a client that uses the generated OpenAPI client.
type Client struct {
	client *restclient.ClientWithResponses
}

// applyCommonHeaders sets the headers Trade Republic's web API expects on auth requests,
// including the AWS WAF anti-bot token (as both header and cookie) when TR_WAF_TOKEN is set.
// The WAF token is short-lived; obtain it from a browser via window.AwsWafIntegration.getToken()
// or let the waf package generate one with a headless browser.
func applyCommonHeaders(req *http.Request) {
	req.Header.Set("User-Agent", internal.HTTPUserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", "https://app.traderepublic.com")
	req.Header.Set("X-TR-Platform", "web")
	req.Header.Set("X-TR-App-Version", internal.TRAppVersion)

	deviceInfo := internal.TRDeviceInfo
	if override := os.Getenv("TR_DEVICE_INFO"); override != "" {
		deviceInfo = override
	}

	req.Header.Set("X-TR-Device-Info", deviceInfo)

	if waf := os.Getenv("TR_WAF_TOKEN"); waf != "" {
		req.Header.Set("X-aws-waf-token", waf)
		req.Header.Add("Cookie", "aws-waf-token="+waf)
	}
}

// NewClient creates a new client that uses the generated OpenAPI client.
func NewClient() (*Client, error) {
	reqEditor := func(_ context.Context, req *http.Request) error {
		applyCommonHeaders(req)
		req.Header.Set("Content-Type", "application/json")

		return nil
	}

	// Create the client with the base URL and request editor
	client, err := restclient.NewClientWithResponses(
		internal.RestAPIBaseURI,
		restclient.WithRequestEditorFn(reqEditor),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create REST client: %w", err)
	}

	return &Client{
		client: client,
	}, nil
}

// loginStatusResponse is the JSON body of the login process status endpoint.
type loginStatusResponse struct {
	Status string `json:"status"`
}

// PollLoginStatus checks a login process. Trade Republic web login is approved in the
// mobile app (push), so callers poll until the status is "CONFIRMED", at which point the
// response carries the tr_session/tr_refresh cookies.
func (c *Client) PollLoginStatus(ctx context.Context, processID string) (string, []*http.Cookie, error) {
	endpoint := "https://" + internal.WebsocketBaseHost + "/api/v2/auth/web/login/processes/" + processID

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", nil, fmt.Errorf("could not build poll request: %w", err)
	}

	applyCommonHeaders(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("could not poll login status: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= statusCodeError {
		return "", nil, fmt.Errorf("login status poll failed with status %d: %s", resp.StatusCode, string(body))
	}

	var parsed loginStatusResponse
	_ = json.Unmarshal(body, &parsed)

	return parsed.Status, resp.Cookies(), nil
}

// Login logs in with phone number and PIN.
func (c *Client) Login(requestBody restclient.APILoginRequest) (string, error) {
	// Make the login request
	resp, err := c.client.LoginWithResponse(context.Background(), requestBody)
	if err != nil {
		return "", fmt.Errorf("could not login: %w", err)
	}

	// Check for error response
	if resp.StatusCode() >= statusCodeError {
		return "", fmt.Errorf(
			"login failed with status code %d: %s",
			resp.StatusCode(),
			string(resp.Body),
		)
	}

	// Extract the process ID from the response
	var processID string
	if resp.JSON200 != nil && resp.JSON200.ProcessId != nil {
		processID = *resp.JSON200.ProcessId
	}

	return processID, nil
}

// RefreshSession exchanges the refresh token for a fresh session token.
// TR returns the new token in the tr_session cookie of GET /api/v1/auth/web/session.
func (c *Client) RefreshSession(refreshToken string) (string, error) {
	cookieEditor := func(_ context.Context, req *http.Request) error {
		cookie := "tr_refresh=" + refreshToken
		if waf := os.Getenv("TR_WAF_TOKEN"); waf != "" {
			cookie += "; aws-waf-token=" + waf
		}
		// Overwrite any Cookie set by the common editor so we send a single, complete header.
		req.Header.Set("Cookie", cookie)

		return nil
	}

	resp, err := c.client.RefreshSessionWithResponse(context.Background(), cookieEditor)
	if err != nil {
		return "", fmt.Errorf("could not refresh session: %w", err)
	}

	if resp.StatusCode() >= statusCodeError {
		return "", fmt.Errorf(
			"session refresh failed with status code %d: %s",
			resp.StatusCode(),
			string(resp.Body),
		)
	}

	for _, cookie := range resp.HTTPResponse.Cookies() {
		if cookie.Name == "tr_session" {
			return cookie.Value, nil
		}
	}

	return "", errors.New("no tr_session cookie in refresh response")
}

// PostOTP verifies the OTP.
func (c *Client) PostOTP(processID, otp string) ([]*http.Cookie, error) {
	if processID == "" {
		return nil, errors.New("processID cannot be empty")
	}

	// Make the OTP verification request
	resp, err := c.client.VerifyOTPWithResponse(context.Background(), processID, otp)
	if err != nil {
		return nil, fmt.Errorf("could not validate otp: %w", err)
	}

	// Check for error response
	if resp.StatusCode() >= statusCodeError {
		return nil, fmt.Errorf(
			"OTP verification failed with status code %d: %s",
			resp.StatusCode(),
			string(resp.Body),
		)
	}

	// Return all cookies from the response
	return resp.HTTPResponse.Cookies(), nil
}
