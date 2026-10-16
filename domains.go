package onlydns

import (
	"context"
	"net/url"
	"strconv"
)

// CreateDomain creates a new DNS domain.
func (c *Client) CreateDomain(ctx context.Context, domain string) error {
	req := CreateDomainRequest{Domain: domain}
	return c.request(ctx, "POST", "/dns", nil, req, nil)
}

// ListDomains lists all domain names managed by the account.
func (c *Client) ListDomains(ctx context.Context, opts ...ListDomainsOptions) ([]string, error) {
	query := url.Values{}
	if len(opts) > 0 {
		if opts[0].Offset > 0 {
			query.Set("offset", strconv.Itoa(opts[0].Offset))
		}
		if opts[0].Limit > 0 {
			query.Set("limit", strconv.Itoa(opts[0].Limit))
		}
	}

	var domains []string
	if err := c.request(ctx, "GET", "/dns", query, nil, &domains); err != nil {
		return nil, err
	}
	if domains == nil {
		domains = []string{}
	}
	return domains, nil
}
