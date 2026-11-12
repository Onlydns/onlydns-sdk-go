package onlydns

import (
	"context"
)

// GetAccount retrieves account metadata, contact details, and current billing package feature entitlements.
func (c *Client) GetAccount(ctx context.Context) (*AccountInfo, error) {
	var info AccountInfo
	if err := c.request(ctx, "GET", "/account", nil, nil, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// GetAccountBilling retrieves the account billing status, balances, and non-payment suspension state.
func (c *Client) GetAccountBilling(ctx context.Context) (*BillingStatusResponse, error) {
	var billing BillingStatusResponse
	if err := c.request(ctx, "GET", "/account/billing", nil, nil, &billing); err != nil {
		return nil, err
	}
	return &billing, nil
}

// GetAccountMetrics retrieves real-time account resource usage and plan feature limits.
func (c *Client) GetAccountMetrics(ctx context.Context) (*AccountMetricsResponse, error) {
	var metrics AccountMetricsResponse
	if err := c.request(ctx, "GET", "/account/metrics", nil, nil, &metrics); err != nil {
		return nil, err
	}
	return &metrics, nil
}

// GetAccountOidc retrieves custom OIDC Single Sign-On configuration, enforcement policy, and non-compliant users.
func (c *Client) GetAccountOidc(ctx context.Context) (*AccountOidcResponse, error) {
	var oidc AccountOidcResponse
	if err := c.request(ctx, "GET", "/account/oidc", nil, nil, &oidc); err != nil {
		return nil, err
	}
	return &oidc, nil
}

// SaveAccountOidc creates or updates custom OIDC Single Sign-On configuration and enforcement settings.
func (c *Client) SaveAccountOidc(ctx context.Context, req *SaveAccountOidcRequest) (*AccountOidcResponse, error) {
	var oidc AccountOidcResponse
	if err := c.request(ctx, "POST", "/account/oidc", nil, req, &oidc); err != nil {
		return nil, err
	}
	return &oidc, nil
}

// DeleteAccountOidc removes custom OIDC Single Sign-On configuration from the account.
func (c *Client) DeleteAccountOidc(ctx context.Context) (*AccountOidcDeleteResponse, error) {
	var res AccountOidcDeleteResponse
	if err := c.request(ctx, "DELETE", "/account/oidc", nil, nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// TestAccountOidc tests OIDC discovery URL reachability and retrieves identity provider endpoint metadata.
func (c *Client) TestAccountOidc(ctx context.Context, req *AccountOidcTestRequest) (*AccountOidcTestResponse, error) {
	var res AccountOidcTestResponse
	if err := c.request(ctx, "POST", "/account/oidc/test", nil, req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
