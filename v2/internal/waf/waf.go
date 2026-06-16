// Package waf generates the AWS WAF anti-bot token that Trade Republic's web API
// requires on auth endpoints (header X-aws-waf-token). The token is produced by the
// AWS WAF challenge script that ships with app.traderepublic.com and can only be
// computed in a real browser, so we drive a headless Chrome to obtain it.
package waf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"

	"github.com/dhojayev/traderepublic-portfolio-downloader/v2/internal"
)

// appURL is the Trade Republic web app; its index loads the AWS WAF challenge script.
const appURL = "https://app.traderepublic.com/"

// DefaultTimeout is how long to wait for the challenge to produce a token.
const DefaultTimeout = 30 * time.Second

// GetToken launches a headless Chrome, lets the AWS WAF challenge run, and returns a
// fresh token suitable for the X-aws-waf-token header / aws-waf-token cookie.
func GetToken(parent context.Context, logger *slog.Logger, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.UserAgent(internal.HTTPUserAgent),
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
	)

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(parent, opts...)
	defer cancelAlloc()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	ctx, cancelTimeout := context.WithTimeout(ctx, timeout)
	defer cancelTimeout()

	logger.Info("Generating AWS WAF token via headless browser", "timeout", timeout)

	var token string

	err := chromedp.Run(ctx,
		chromedp.Navigate(appURL),
		// Wait until the challenge has registered its integration object.
		chromedp.Poll(
			"!!(window.AwsWafIntegration && window.AwsWafIntegration.getToken)",
			nil,
			chromedp.WithPollingTimeout(timeout),
		),
		// getToken() returns a Promise; await it.
		chromedp.Evaluate(
			"window.AwsWafIntegration.getToken()",
			&token,
			func(p *runtime.EvaluateParams) *runtime.EvaluateParams {
				return p.WithAwaitPromise(true)
			},
		),
	)
	if err != nil {
		return "", fmt.Errorf("waf token generation failed: %w", err)
	}

	if token == "" {
		return "", errors.New("waf token generator returned an empty token")
	}

	logger.Info("AWS WAF token generated", "length", len(token))

	return token, nil
}
