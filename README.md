# OnlyDNS Go SDK

Official Go SDK for [OnlyDNS](https://www.onlydns.com) to programmatically manage authoritative Anycast DNS zones, records, 1-click DNSSEC, and RFC 2136 TSIG keys. Learn more in the [OnlyDNS Technical How-To Guides](https://www.onlydns.com/howto/).

```bash
go get github.com/onlydns/onlydns-sdk-go
```

**Authentication Environment Variable:** `ONLYDNS_API_TOKEN`.

## Features

- **Idiomatic Go**: Context-aware API calls, clean error handling, and zero external dependencies.
- **High-Level Atomic Helpers**: Convenient methods (`AddRecord`, `RemoveRecord`, `UpdateRecord`, `FindRecords`) that manage read-modify-write cycles over bulk replacement.
- **Complete TSIG Key Management**: Generate and assign TSIG keys with fine-grained AXFR / DNS update permissions.
- **Environment Auto-Detection**: Automatically reads token from `ONLYDNS_API_TOKEN`.

## Installation

```bash
go get github.com/onlydns/onlydns-sdk-go
```

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/onlydns/onlydns-sdk-go"
)

func main() {
	ctx := context.Background()

	// Initialize client (defaults to ONLYDNS_API_TOKEN from environment)
	client, err := onlydns.NewClient("your_api_token_here")
	if err != nil {
		log.Fatalf("Failed to initialize client: %v", err)
	}

	// 1. List Domains
	domains, err := client.ListDomains(ctx)
	if err != nil {
		log.Fatalf("Failed to list domains: %v", err)
	}
	fmt.Printf("Domains: %v\n", domains)

	// 2. Fetch DNS Records
	records, err := client.GetRecords(ctx, "example.com")
	if err != nil {
		log.Fatalf("Failed to get records: %v", err)
	}
	for _, r := range records {
		fmt.Printf("%s (%s): %v [TTL %d]\n", r.Name, r.Type, r.Records, r.TTL)
	}

	// 3. High-Level Helper: Add an A Record
	_, err = client.AddRecord(ctx, "example.com", "api", onlydns.RecordTypeA, []string{"192.0.2.1"}, 300)
	if err != nil {
		log.Fatalf("Failed to add record: %v", err)
	}

	// 4. High-Level Helper: Update / Upsert CNAME
	_, err = client.UpdateRecord(ctx, "example.com", "www", onlydns.RecordTypeCNAME, []string{"example.com"}, nil)
	if err != nil {
		log.Fatalf("Failed to update record: %v", err)
	}

	// 5. High-Level Helper: Remove Record Value
	valueToRemove := "192.0.2.1"
	recType := onlydns.RecordTypeA
	_, err = client.RemoveRecord(ctx, "example.com", "api", &recType, &valueToRemove)
	if err != nil {
		log.Fatalf("Failed to remove record: %v", err)
	}
}
```

## TSIG Key Management

```go
// List TSIG Keys
keys, err := client.GetTsigKeys(ctx)

// Create a new TSIG key
key, err := client.CreateTsigKey(ctx, onlydns.TsigAlgorithmHmacSHA256)
fmt.Printf("Created TSIG Key: %s\n", key.Name)

// Update domain TSIG permissions
err = client.UpdateDomainTsig(ctx, "example.com", key.Name, true, true)

// Delete all TSIG keys on a domain
err = client.DeleteDomainTsig(ctx, "example.com")
```

## DNSSEC & Domain Creation

```go
// Create a new domain
err = client.CreateDomain(ctx, "my-new-domain.com")

// Get DNSSEC status & DS keys
dnssec, err := client.GetDnssecStatus(ctx, "my-new-domain.com")
if err != nil {
	log.Fatalf("Failed to get dnssec status: %v", err)
}
fmt.Printf("DNSSEC Enabled: %v\n", dnssec.Enabled)
for _, key := range dnssec.Keys {
	fmt.Printf("KeyTag: %d, Digest: %s\n", key.KeyTag, key.Digest)
}

// Enable DNSSEC
err = client.EnableDnssec(ctx, "my-new-domain.com")

// Disable DNSSEC
err = client.DisableDnssec(ctx, "my-new-domain.com")
```

## License

MIT License.
