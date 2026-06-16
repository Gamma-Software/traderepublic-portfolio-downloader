package internal

import "time"

const (
	// RestAPIBaseURI Trade Republic's REST API base URI.
	// Trailing slash is required: oapi-codegen resolves operation paths relatively
	// (e.g. "./auth/web/login"), and without it RFC 3986 resolution drops the "/v1" segment.
	RestAPIBaseURI = "https://api.traderepublic.com/api/v1/"

	// WebsocketBaseHost Trade Republic's websocket base host.
	WebsocketBaseHost = "api.traderepublic.com"

	// HTTPUserAgent used for all HTTP communications.
	HTTPUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"

	// SessionRefreshInterval represents in how many seconds session has to be refreshed to keep it alive.
	SessionRefreshInterval = 120

	AuthTokenFilename = "./.auth"

	// TRAppVersion sent as X-TR-App-Version on auth endpoints.
	TRAppVersion = "15.65.6"

	// TRDeviceInfo sent as X-TR-Device-Info (base64 JSON device fingerprint) on auth endpoints.
	// This is a generic, non-personal default; the stableDeviceId is client-generated and not
	// validated by TR. Override with the TR_DEVICE_INFO env var to use your own browser's value.
	TRDeviceInfo = "eyJzdGFibGVEZXZpY2VJZCI6IjcxY2I3MzgxMjRkN2Y2YWE0ZTJiMjY0YmIxODQ4OWY1NTIwYWZkYzAwYjRjMzU0ODAzYTYwOThmZDYxYmQwZDFiNjdkY2YzNGQyMWI2ZTRmNTU4ZmNjNTA0NjU1ZjQ5NGI2YTczYzUxNDRkMWQ1NWZhY2MxMjkyMDAzZmU0YTEwIiwibW9kZWwiOiJBcHBsZSBNYWNpbnRvc2giLCJicm93c2VyIjoiU2FmYXJpIiwiYnJvd3NlclZlcnNpb24iOiIyNi41Iiwib3MiOiJNYWMgT1MiLCJvc1ZlcnNpb24iOiIxMC4xNS43IiwidGltZXpvbmUiOiJFdXJvcGUvQmVybGluIiwidGltZXpvbmVPZmZzZXQiOi02MCwic2NyZWVuIjoiMTkyMHgxMDgweDI0IiwicHJlZmVycmVkTGFuZ3VhZ2VzIjpbImVuLVVTIl0sIm51bWJlck9mQ29yZXMiOjh9"

	// ResponseActionTypeTimelineDetail represents the value the app will look for in order to determine
	// if any details can be fetched.
	ResponseActionTypeTimelineDetail = "timelineDetail"

	// ResponseTimeFormat represents the default date time format in the response.
	ResponseTimeFormat = "2006-01-02T15:04:05-0700"

	// ResponseTimeFormatAlt represents the alternative date time format in the response.
	ResponseTimeFormatAlt = time.RFC3339Nano

	// CSVFilename filename under which a CSV file with transaction entries has to be saved.
	CSVFilename = "./transactions.csv"

	// TransactionDocumentsBaseDir base directory under which downloaded transaction documents are saved.
	TransactionDocumentsBaseDir = "./documents/transactions"

	// ActivityLogDocumentsBaseDir base directory under which downloaded activity documents are saved.
	ActivityLogDocumentsBaseDir = "./documents/activity"
)
