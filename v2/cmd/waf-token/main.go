// Command waf-token prints a fresh Trade Republic AWS WAF token to stdout, generated via a
// headless browser. Useful for exporting TR_WAF_TOKEN manually:
//
//	export TR_WAF_TOKEN="$(go run ./cmd/waf-token)"
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/dhojayev/traderepublic-portfolio-downloader/v2/internal/waf"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	token, err := waf.GetToken(context.Background(), logger, waf.DefaultTimeout)
	if err != nil {
		logger.Error("Failed to generate WAF token", "error", err)
		os.Exit(1)
	}

	fmt.Println(token)
}
