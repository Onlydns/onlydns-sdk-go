package onlydns

import (
	"context"
	"fmt"
	"net/url"
)

// GetTsigKeys retrieves all TSIG keys for the account.
func (c *Client) GetTsigKeys(ctx context.Context) ([]TsigKey, error) {
	var resp TsigKeysResponse
	if err := c.request(ctx, "GET", "/dns/tsig", nil, nil, &resp); err != nil {
		return nil, err
	}
	if resp.TsigKeys == nil {
		return []TsigKey{}, nil
	}
	return resp.TsigKeys, nil
}

// CreateTsigKey creates a new TSIG key on the account.
func (c *Client) CreateTsigKey(ctx context.Context, algorithm TsigAlgorithm) (*TsigKey, error) {
	var body *CreateTsigKeyRequest
	if algorithm != "" {
		body = &CreateTsigKeyRequest{Algorithm: algorithm}
	}

	var key TsigKey
	if err := c.request(ctx, "POST", "/dns/tsig", nil, body, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// GetTsigKey retrieves details for a specific TSIG key.
func (c *Client) GetTsigKey(ctx context.Context, keyName string) (*TsigKey, error) {
	encodedKey := url.PathEscape(keyName)
	path := fmt.Sprintf("/dns/tsig/%s", encodedKey)

	var key TsigKey
	if err := c.request(ctx, "GET", path, nil, nil, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// DeleteDomainTsig deletes all TSIG keys on a domain.
func (c *Client) DeleteDomainTsig(ctx context.Context, domainName string) error {
	encodedDomain := url.PathEscape(domainName)
	path := fmt.Sprintf("/dns/%s/tsig", encodedDomain)

	return c.request(ctx, "DELETE", path, nil, nil, nil)
}

// UpdateDomainTsig updates TSIG key permissions for a domain.
func (c *Client) UpdateDomainTsig(ctx context.Context, domainName, keyName string, allowAxfr, allowDnsUpdate bool) error {
	encodedDomain := url.PathEscape(domainName)
	encodedKey := url.PathEscape(keyName)
	path := fmt.Sprintf("/dns/%s/tsig/%s", encodedDomain, encodedKey)

	body := DomainTsigPermissions{
		AllowAxfr:      allowAxfr,
		AllowDnsUpdate: allowDnsUpdate,
	}

	return c.request(ctx, "PATCH", path, nil, body, nil)
}
