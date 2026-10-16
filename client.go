package onlydns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const DefaultBaseURL = "https://api.onlydns.com/v1"

// Client is the OnlyDNS API client.
type Client struct {
	APIToken   string
	BaseURL    string
	HTTPClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithBaseURL overrides the default API base URL.
func WithBaseURL(baseURL string) Option {
	return func(c *Client) {
		c.BaseURL = strings.TrimRight(baseURL, "/")
	}
}

// WithHTTPClient overrides the default http.Client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(c *Client) {
		c.HTTPClient = httpClient
	}
}

// WithTimeout sets a timeout on the default HTTP client.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) {
		c.HTTPClient.Timeout = timeout
	}
}

// NewClient initializes a new OnlyDNS Client.
// If apiToken is empty, it attempts to load from ONLYDNS_API_KEY or ONLYDNS_API_TOKEN environment variables.
func NewClient(apiToken string, opts ...Option) (*Client, error) {
	token := apiToken
	if token == "" {
		token = os.Getenv("ONLYDNS_API_KEY")
		if token == "" {
			token = os.Getenv("ONLYDNS_API_TOKEN")
		}
	}
	if token == "" {
		return nil, &AuthenticationError{
			APIError: APIError{
				StatusCode: 401,
				Message:    "API token is required. Pass apiToken or set ONLYDNS_API_KEY environment variable",
			},
		}
	}

	c := &Client{
		APIToken: token,
		BaseURL:  DefaultBaseURL,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

func (c *Client) request(ctx context.Context, method, path string, query url.Values, body interface{}, out interface{}) error {
	relURL := strings.TrimLeft(path, "/")
	reqURL := fmt.Sprintf("%s/%s", c.BaseURL, relURL)
	if len(query) > 0 {
		reqURL += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to encode request body: %w", err)
		}
		bodyReader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "OnlyDNS-Go-SDK/1.0.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErrResp APIErrorResponse
		_ = json.Unmarshal(respBytes, &apiErrResp)

		title := apiErrResp.Title
		if title == "" {
			title = http.StatusText(resp.StatusCode)
		}

		baseErr := APIError{
			StatusCode: resp.StatusCode,
			Message:    title,
			Details:    apiErrResp.Description,
		}

		switch resp.StatusCode {
		case http.StatusBadRequest:
			return &ValidationError{APIError: baseErr}
		case http.StatusUnauthorized:
			if baseErr.Message == "" {
				baseErr.Message = "Access token is missing or invalid"
			}
			return &AuthenticationError{APIError: baseErr}
		case http.StatusNotFound:
			if baseErr.Message == "" {
				baseErr.Message = "Resource not found"
			}
			return &NotFoundError{APIError: baseErr}
		default:
			return &baseErr
		}
	}

	if out != nil && len(respBytes) > 0 {
		if err := json.Unmarshal(respBytes, out); err != nil {
			return fmt.Errorf("failed to decode response JSON: %w", err)
		}
	}

	return nil
}
