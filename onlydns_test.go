package onlydns_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/onlydns/onlydns-sdk-go"
)

func TestClientAuthMissing(t *testing.T) {
	t.Setenv("ONLYDNS_API_TOKEN", "")

	_, err := onlydns.NewClient("")
	if err == nil {
		t.Fatalf("expected error when token is missing")
	}
}

func TestListDomains(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test_token" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/dns" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode([]string{"example.com", "example.net"})
	}))
	defer ts.Close()

	client, err := onlydns.NewClient("test_token", onlydns.WithBaseURL(ts.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	domains, err := client.ListDomains(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(domains) != 2 || domains[0] != "example.com" {
		t.Errorf("unexpected domains returned: %v", domains)
	}
}

func TestAddRecordHelper(t *testing.T) {
	var putRecords []onlydns.DNSRecord

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/dns/example.com/records" {
			json.NewEncoder(w).Encode([]onlydns.DNSRecord{
				{Name: "mail", Type: onlydns.RecordTypeA, TTL: 300, Records: []string{"192.0.2.1"}},
			})
			return
		}
		if r.Method == "PUT" && r.URL.Path == "/dns/example.com/records" {
			json.NewDecoder(r.Body).Decode(&putRecords)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client, err := onlydns.NewClient("test_token", onlydns.WithBaseURL(ts.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	updated, err := client.AddRecord(context.Background(), "example.com", "mail", onlydns.RecordTypeA, []string{"192.0.2.2"}, 600)
	if err != nil {
		t.Fatalf("failed to add record: %v", err)
	}

	if len(updated) != 1 {
		t.Fatalf("expected 1 record group, got %d", len(updated))
	}
	if len(updated[0].Records) != 2 || updated[0].Records[1] != "192.0.2.2" {
		t.Errorf("unexpected records: %v", updated[0].Records)
	}
	if updated[0].TTL != 600 {
		t.Errorf("expected TTL 600, got %d", updated[0].TTL)
	}
}

func TestFindRecords(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/dns/example.com/records" {
			json.NewEncoder(w).Encode([]onlydns.DNSRecord{
				{Name: "api.example.com.", Type: onlydns.RecordTypeA, TTL: 300, Records: []string{"192.0.2.1"}},
				{Name: "mail.example.com.", Type: onlydns.RecordTypeA, TTL: 300, Records: []string{"192.0.2.25"}},
				{Name: "www.example.com.", Type: onlydns.RecordTypeCNAME, TTL: 600, Records: []string{"example.com."}},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client, err := onlydns.NewClient("test_token", onlydns.WithBaseURL(ts.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	val := "192.0.2.25"
	found, err := client.FindRecords(context.Background(), "example.com", nil, nil, &val)
	if err != nil {
		t.Fatalf("failed to find records: %v", err)
	}
	if len(found) != 1 || found[0].Name != "mail.example.com." {
		t.Errorf("expected mail record, got: %+v", found)
	}

	nameSub := "mail"
	foundName, err := client.FindRecords(context.Background(), "example.com", &nameSub, nil, nil)
	if err != nil {
		t.Fatalf("failed to find records by name substring: %v", err)
	}
	if len(foundName) != 1 || foundName[0].Name != "mail.example.com." {
		t.Errorf("expected mail record by substring, got: %+v", foundName)
	}

	allSub := "example"
	foundAll, err := client.FindRecords(context.Background(), "example.com", &allSub, nil, nil)
	if err != nil {
		t.Fatalf("failed to find all records by domain substring: %v", err)
	}
	if len(foundAll) != 3 {
		t.Errorf("expected 3 records, got %d", len(foundAll))
	}
}

func TestTSIGOperations(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/dns/tsig" {
			json.NewEncoder(w).Encode(onlydns.TsigKey{
				Name:      "key-1",
				Algorithm: onlydns.TsigAlgorithmHmacSHA256,
				Key:       "secret123",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client, err := onlydns.NewClient("test_token", onlydns.WithBaseURL(ts.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	key, err := client.CreateTsigKey(context.Background(), onlydns.TsigAlgorithmHmacSHA256)
	if err != nil {
		t.Fatalf("failed to create tsig key: %v", err)
	}

	if key.Name != "key-1" || key.Algorithm != onlydns.TsigAlgorithmHmacSHA256 {
		t.Errorf("unexpected key created: %+v", key)
	}
}

func TestCreateDomain(t *testing.T) {
	var createdReq onlydns.CreateDomainRequest
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.URL.Path == "/dns" {
			json.NewDecoder(r.Body).Decode(&createdReq)
			w.WriteHeader(http.StatusCreated)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client, err := onlydns.NewClient("test_token", onlydns.WithBaseURL(ts.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	err = client.CreateDomain(context.Background(), "newexample.com")
	if err != nil {
		t.Fatalf("unexpected error creating domain: %v", err)
	}

	if createdReq.Domain != "newexample.com" {
		t.Errorf("expected domain newexample.com, got %s", createdReq.Domain)
	}
}

func TestDNSSECOperations(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/dns/example.com/dnssec" {
			json.NewEncoder(w).Encode(onlydns.DNSSECStatus{
				Enabled:    true,
				Nsec3param: "1 0 10 12345678",
				Keys: []onlydns.DNSSECDsKey{
					{
						KeyTag:     2371,
						Algorithm:  onlydns.DNSSECKeyAlgorithmECDSAP256SHA256,
						DigestType: onlydns.DNSSECKeyDigestTypeSHA256,
						Digest:     "abc123def456",
					},
				},
			})
			return
		}
		if r.Method == "POST" && r.URL.Path == "/dns/example.com/dnssec" {
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.Method == "DELETE" && r.URL.Path == "/dns/example.com/dnssec" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client, err := onlydns.NewClient("test_token", onlydns.WithBaseURL(ts.URL))
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	status, err := client.GetDnssecStatus(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error getting dnssec status: %v", err)
	}

	if !status.Enabled || status.Nsec3param != "1 0 10 12345678" || len(status.Keys) != 1 {
		t.Errorf("unexpected dnssec status: %+v", status)
	}
	if status.Keys[0].KeyTag != 2371 || status.Keys[0].Algorithm != onlydns.DNSSECKeyAlgorithmECDSAP256SHA256 {
		t.Errorf("unexpected key details: %+v", status.Keys[0])
	}

	if err := client.EnableDnssec(context.Background(), "example.com"); err != nil {
		t.Fatalf("unexpected error enabling dnssec: %v", err)
	}

	if err := client.DisableDnssec(context.Background(), "example.com"); err != nil {
		t.Fatalf("unexpected error disabling dnssec: %v", err)
	}
}
