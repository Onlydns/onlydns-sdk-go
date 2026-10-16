package onlydns

import (
	"context"
	"fmt"
	"net/url"
)

// GetDnssecStatus returns the DNSSEC status and DS keys for a domain.
func (c *Client) GetDnssecStatus(ctx context.Context, domainName string) (*DNSSECStatus, error) {
	encoded := url.PathEscape(domainName)
	path := fmt.Sprintf("/dns/%s/dnssec", encoded)

	var status DNSSECStatus
	if err := c.request(ctx, "GET", path, nil, nil, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// EnableDnssec enables DNSSEC for a domain.
func (c *Client) EnableDnssec(ctx context.Context, domainName string) error {
	encoded := url.PathEscape(domainName)
	path := fmt.Sprintf("/dns/%s/dnssec", encoded)
	return c.request(ctx, "POST", path, nil, nil, nil)
}

// DisableDnssec disables DNSSEC for a domain.
func (c *Client) DisableDnssec(ctx context.Context, domainName string) error {
	encoded := url.PathEscape(domainName)
	path := fmt.Sprintf("/dns/%s/dnssec", encoded)
	return c.request(ctx, "DELETE", path, nil, nil, nil)
}
