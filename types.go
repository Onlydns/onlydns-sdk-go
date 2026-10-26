package onlydns

// RecordType defines supported DNS record types.
type RecordType string

const (
	RecordTypeA      RecordType = "A"
	RecordTypeAAAA   RecordType = "AAAA"
	RecordTypeMX     RecordType = "MX"
	RecordTypeCNAME  RecordType = "CNAME"
	RecordTypeTXT    RecordType = "TXT"
	RecordTypeSRV    RecordType = "SRV"
	RecordTypeCAA    RecordType = "CAA"
	RecordTypeCERT   RecordType = "CERT"
	RecordTypeHTTPS  RecordType = "HTTPS"
	RecordTypeLOC    RecordType = "LOC"
	RecordTypeNAPTR  RecordType = "NAPTR"
	RecordTypeNS     RecordType = "NS"
	RecordTypeSMIMEA RecordType = "SMIMEA"
	RecordTypeSSHFP  RecordType = "SSHFP"
	RecordTypeSVCB   RecordType = "SVCB"
	RecordTypeTLSA   RecordType = "TLSA"
	RecordTypeURL    RecordType = "URL"
	RecordTypePROXY  RecordType = "PROXY"
)

// TsigAlgorithm defines supported TSIG key algorithms.
type TsigAlgorithm string

const (
	TsigAlgorithmMacMD5     TsigAlgorithm = "mac-md5"
	TsigAlgorithmHmacSHA1   TsigAlgorithm = "hmac-sha1"
	TsigAlgorithmHmacSHA224 TsigAlgorithm = "hmac-sha224"
	TsigAlgorithmHmacSHA256 TsigAlgorithm = "hmac-sha256"
	TsigAlgorithmHmacSHA384 TsigAlgorithm = "hmac-sha384"
	TsigAlgorithmHmacSHA512 TsigAlgorithm = "hmac-sha512"
)

// DNSSECKeyAlgorithm defines supported DNSSEC Key Algorithm numbers.
type DNSSECKeyAlgorithm int

const (
	DNSSECKeyAlgorithmRSAMD5            DNSSECKeyAlgorithm = 1
	DNSSECKeyAlgorithmDiffieHellman     DNSSECKeyAlgorithm = 2
	DNSSECKeyAlgorithmDSASHA1           DNSSECKeyAlgorithm = 3
	DNSSECKeyAlgorithmRSASHA1           DNSSECKeyAlgorithm = 5
	DNSSECKeyAlgorithmDSANSEC3SHA1      DNSSECKeyAlgorithm = 6
	DNSSECKeyAlgorithmRSASHA1NSEC3SHA1  DNSSECKeyAlgorithm = 7
	DNSSECKeyAlgorithmRSASHA256         DNSSECKeyAlgorithm = 8
	DNSSECKeyAlgorithmRSASHA512         DNSSECKeyAlgorithm = 10
	DNSSECKeyAlgorithmGOSTR34102001     DNSSECKeyAlgorithm = 12
	DNSSECKeyAlgorithmECDSAP256SHA256   DNSSECKeyAlgorithm = 13
	DNSSECKeyAlgorithmECDSAP384SHA384   DNSSECKeyAlgorithm = 14
	DNSSECKeyAlgorithmED25519           DNSSECKeyAlgorithm = 15
	DNSSECKeyAlgorithmED448             DNSSECKeyAlgorithm = 16
	DNSSECKeyAlgorithmSM2SM3            DNSSECKeyAlgorithm = 17
	DNSSECKeyAlgorithmECCGOST12         DNSSECKeyAlgorithm = 23
)

// DNSSECKeyDigestType defines supported DNSSEC Key Digest Types.
type DNSSECKeyDigestType int

const (
	DNSSECKeyDigestTypeSHA1        DNSSECKeyDigestType = 1
	DNSSECKeyDigestTypeSHA256      DNSSECKeyDigestType = 2
	DNSSECKeyDigestTypeGOSTR341194 DNSSECKeyDigestType = 3
	DNSSECKeyDigestTypeSHA384      DNSSECKeyDigestType = 4
)

// DNSSECDsKey represents a DNSSEC DS key.
type DNSSECDsKey struct {
	KeyTag     int                 `json:"keyTag"`
	Algorithm  DNSSECKeyAlgorithm  `json:"algorithm"`
	DigestType DNSSECKeyDigestType `json:"digestType"`
	Digest     string              `json:"digest"`
}

// DNSSECStatus represents the DNSSEC status for a domain.
type DNSSECStatus struct {
	Enabled    bool          `json:"enabled"`
	Nsec3param string        `json:"nsec3param,omitempty"`
	Keys       []DNSSECDsKey `json:"keys,omitempty"`
}

// DNSDnssecStatusResponse is an alias for DNSSECStatus.
type DNSDnssecStatusResponse = DNSSECStatus

// CreateDomainRequest represents the request body for POST /dns.
type CreateDomainRequest struct {
	Domain string `json:"domain"`
}

// DNSRecord represents a DNS record entry for a specific name and type.
type DNSRecord struct {
	Name    string     `json:"name"`
	Type    RecordType `json:"type"`
	TTL     int        `json:"ttl"`
	Records []string   `json:"records"`
}

// TsigKey represents a TSIG Key configured on the account.
type TsigKey struct {
	Name      string        `json:"name"`
	Algorithm TsigAlgorithm `json:"algorithm"`
	Key       string        `json:"key"`
}

// TsigKeysResponse represents the response envelope from GET /dns/tsig.
type TsigKeysResponse struct {
	TsigKeys []TsigKey `json:"tsigKeys"`
}

// CreateTsigKeyRequest represents the payload for POST /dns/tsig.
type CreateTsigKeyRequest struct {
	Algorithm TsigAlgorithm `json:"algorithm,omitempty"`
}

// DomainTsigPermissions represents the permissions for a TSIG key on a domain.
type DomainTsigPermissions struct {
	AllowAxfr      bool     `json:"allowAxfr"`
	AllowDnsUpdate bool     `json:"allowDnsUpdate"`
	Subdomains     []string `json:"subdomains,omitempty"`
}

// ListDomainsOptions specifies pagination options for listing domains.
type ListDomainsOptions struct {
	Offset int
	Limit  int
}

// APIErrorResponse represents error responses returned by the OnlyDNS API.
type APIErrorResponse struct {
	Lang        string   `json:"lang,omitempty"`
	ErrorCode   int      `json:"errorCode,omitempty"`
	Title       string   `json:"title,omitempty"`
	Description []string `json:"description,omitempty"`
}
