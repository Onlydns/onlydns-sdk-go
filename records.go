package onlydns

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// GetRecords retrieves all DNS records for a domain.
func (c *Client) GetRecords(ctx context.Context, domainName string) ([]DNSRecord, error) {
	encodedDomain := url.PathEscape(domainName)
	path := fmt.Sprintf("/dns/%s/records", encodedDomain)

	var records []DNSRecord
	if err := c.request(ctx, "GET", path, nil, nil, &records); err != nil {
		return nil, err
	}
	if records == nil {
		records = []DNSRecord{}
	}
	return records, nil
}

// ReplaceRecords replaces all DNS records on a domain (atomic bulk replace).
func (c *Client) ReplaceRecords(ctx context.Context, domainName string, records []DNSRecord) error {
	encodedDomain := url.PathEscape(domainName)
	path := fmt.Sprintf("/dns/%s/records", encodedDomain)

	return c.request(ctx, "PUT", path, nil, records, nil)
}

// AddRecord adds or merges DNS record values for a specific hostname and type.
func (c *Client) AddRecord(ctx context.Context, domainName, name string, recordType RecordType, records []string, ttl int) ([]DNSRecord, error) {
	current, err := c.GetRecords(ctx, domainName)
	if err != nil {
		return nil, err
	}

	found := false
	typeUpper := strings.ToUpper(string(recordType))

	for i := range current {
		if strings.EqualFold(current[i].Name, name) && strings.ToUpper(string(current[i].Type)) == typeUpper {
			for _, val := range records {
				exists := false
				for _, existingVal := range current[i].Records {
					if existingVal == val {
						exists = true
						break
					}
				}
				if !exists {
					current[i].Records = append(current[i].Records, val)
				}
			}
			if ttl > 0 {
				current[i].TTL = ttl
			}
			found = true
			break
		}
	}

	if !found {
		if ttl <= 0 {
			ttl = 300
		}
		current = append(current, DNSRecord{
			Name:    name,
			Type:    recordType,
			TTL:     ttl,
			Records: records,
		})
	}

	if err := c.ReplaceRecords(ctx, domainName, current); err != nil {
		return nil, err
	}

	return current, nil
}

// RemoveRecord removes a matching DNS record or a specific value from a domain.
func (c *Client) RemoveRecord(ctx context.Context, domainName, name string, recordType *RecordType, value *string) ([]DNSRecord, error) {
	current, err := c.GetRecords(ctx, domainName)
	if err != nil {
		return nil, err
	}

	var updated []DNSRecord
	var typeUpper *string
	if recordType != nil {
		s := strings.ToUpper(string(*recordType))
		typeUpper = &s
	}

	for _, rec := range current {
		nameMatches := strings.EqualFold(rec.Name, name)
		typeMatches := typeUpper == nil || strings.ToUpper(string(rec.Type)) == *typeUpper

		if nameMatches && typeMatches {
			if value != nil {
				var remaining []string
				for _, val := range rec.Records {
					if val != *value {
						remaining = append(remaining, val)
					}
				}
				if len(remaining) > 0 {
					rec.Records = remaining
					updated = append(updated, rec)
				}
			}
			// If value is nil, record is omitted
		} else {
			updated = append(updated, rec)
		}
	}

	if err := c.ReplaceRecords(ctx, domainName, updated); err != nil {
		return nil, err
	}

	return updated, nil
}

// UpdateRecord replaces all values for a specific hostname and type combination.
func (c *Client) UpdateRecord(ctx context.Context, domainName, name string, recordType RecordType, records []string, ttl *int) ([]DNSRecord, error) {
	current, err := c.GetRecords(ctx, domainName)
	if err != nil {
		return nil, err
	}

	found := false
	typeUpper := strings.ToUpper(string(recordType))

	for i := range current {
		if strings.EqualFold(current[i].Name, name) && strings.ToUpper(string(current[i].Type)) == typeUpper {
			current[i].Records = records
			if ttl != nil {
				current[i].TTL = *ttl
			}
			found = true
			break
		}
	}

	if !found {
		recordTTL := 300
		if ttl != nil {
			recordTTL = *ttl
		}
		current = append(current, DNSRecord{
			Name:    name,
			Type:    recordType,
			TTL:     recordTTL,
			Records: records,
		})
	}

	if err := c.ReplaceRecords(ctx, domainName, current); err != nil {
		return nil, err
	}

	return current, nil
}

// FindRecords searches and filters DNS records by name, type, and/or value without altering zone data.
func (c *Client) FindRecords(ctx context.Context, domainName string, name *string, recordType *RecordType, value *string) ([]DNSRecord, error) {
	records, err := c.GetRecords(ctx, domainName)
	if err != nil {
		return nil, err
	}

	var nameLower *string
	if name != nil {
		s := strings.ToLower(strings.TrimSpace(*name))
		nameLower = &s
	}

	var filtered []DNSRecord
	var typeUpper *string
	if recordType != nil {
		s := strings.ToUpper(string(*recordType))
		typeUpper = &s
	}

	for _, rec := range records {
		if nameLower != nil && !strings.Contains(strings.ToLower(rec.Name), *nameLower) {
			continue
		}
		if typeUpper != nil && strings.ToUpper(string(rec.Type)) != *typeUpper {
			continue
		}
		if value != nil {
			valLower := strings.ToLower(strings.TrimSpace(*value))
			matched := false
			for _, v := range rec.Records {
				if strings.Contains(strings.ToLower(v), valLower) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		filtered = append(filtered, rec)
	}

	return filtered, nil
}
