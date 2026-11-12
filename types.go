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

// AccountPostalAddress represents an account contact postal address.
type AccountPostalAddress struct {
	Street1    string `json:"street1,omitempty"`
	Street2    string `json:"street2,omitempty"`
	Street3    string `json:"street3,omitempty"`
	City       string `json:"city,omitempty"`
	State      string `json:"state,omitempty"`
	CountryID  string `json:"countryId,omitempty"`
	PostalCode string `json:"postalCode,omitempty"`
}

// BillingPackageFeatures represents feature capabilities included in the billing package.
type BillingPackageFeatures struct {
	Domains   int  `json:"domains"`
	Records   int  `json:"records"`
	Queries   int  `json:"queries"`
	DNSSEC    bool `json:"dnssec"`
	TSIG      bool `json:"tsig"`
	Proxy     bool `json:"proxy"`
	CustomSSO bool `json:"customSSO"`
}

// BillingPackage represents billing package details and feature entitlements.
type BillingPackage struct {
	ID          string                 `json:"id"`
	Description string                 `json:"description"`
	Amount      float64                `json:"amount"`
	Features    BillingPackageFeatures `json:"features"`
}

// AccountInfo represents account information and feature entitlements.
type AccountInfo struct {
	AccountID   string                `json:"accountId"`
	ActiveAt    *string               `json:"activeAt,omitempty"`
	CompanyName string                `json:"companyName,omitempty"`
	FirstName   string                `json:"firstName,omitempty"`
	LastName    string                `json:"lastName,omitempty"`
	Address     *AccountPostalAddress `json:"address,omitempty"`
	Package     *BillingPackage       `json:"package,omitempty"`
}

// Money represents a monetary value with a currency code.
type Money struct {
	Value    string `json:"value"`
	Currency string `json:"currency"`
}

// BillingStatusResponse represents the billing state and balance summary.
type BillingStatusResponse struct {
	AccountID              string  `json:"accountId"`
	Currency               string  `json:"currency"`
	AmountDue              Money   `json:"amountDue"`
	PastDueAmount          Money   `json:"pastDueAmount"`
	BillingAssessedTo      *string `json:"billingAssessedTo,omitempty"`
	SuspendedAt            *string `json:"suspendedAt,omitempty"`
	PastDue                bool    `json:"pastDue"`
	Suspended              bool    `json:"suspended"`
	SuspendedForNonPayment bool    `json:"suspendedForNonPayment"`
	PaymentRequired        bool    `json:"paymentRequired"`
	Payable                bool    `json:"payable"`
}

// AccountMetricUsage represents a usage metric with observed count and plan limit.
type AccountMetricUsage struct {
	Current int `json:"current"`
	Limit   int `json:"limit"`
}

// AccountMetricRecords represents DNS record metrics including portfolio total, peak single-zone record count, peak zone name, and per-zone plan limit.
type AccountMetricRecords struct {
	TotalRecords   int     `json:"totalRecords"`
	MaxZoneRecords int     `json:"maxZoneRecords"`
	MaxZoneName    *string `json:"maxZoneName,omitempty"`
	LimitPerZone   int     `json:"limitPerZone"`
	Current        *int    `json:"current,omitempty"`
	Limit          *int    `json:"limit,omitempty"`
}

// AccountMetricApiRequestsPerMinute represents API request rate metrics including current, 24h average, and limit.
type AccountMetricApiRequestsPerMinute struct {
	Current            int     `json:"current"`
	AverageLast24Hours float64 `json:"averageLast24Hours"`
	Limit              int     `json:"limit"`
}

// AccountMetricDNSSEC represents DNSSEC usage metric and package entitlement status.
type AccountMetricDNSSEC struct {
	Current int  `json:"current"`
	Enabled bool `json:"enabled"`
}

// AccountMetricsUsage represents aggregated usage metrics for an account.
type AccountMetricsUsage struct {
	Domains              AccountMetricUsage                `json:"domains"`
	Records              AccountMetricRecords              `json:"records"`
	Queries              AccountMetricUsage                `json:"queries"`
	DNSSEC               AccountMetricDNSSEC               `json:"dnssec"`
	TSIGKeys             AccountMetricUsage                `json:"tsigKeys"`
	ChangesLast24Hours   AccountMetricUsage                `json:"changesLast24Hours"`
	APIRequestsPerMinute AccountMetricApiRequestsPerMinute `json:"apiRequestsPerMinute"`
	APITokens            AccountMetricUsage                `json:"apiTokens"`
}

// AccountMetricsPackage represents package summary in metrics response.
type AccountMetricsPackage struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// AccountMetricsResponse represents the response returned by GET /account/metrics.
type AccountMetricsResponse struct {
	AccountID string                 `json:"accountId"`
	Package   *AccountMetricsPackage `json:"package,omitempty"`
	Usage     AccountMetricsUsage    `json:"usage"`
}

// AccountOidcNonCompliantUser represents a user who cannot use custom SSO until migration.
type AccountOidcNonCompliantUser struct {
	UserID      string  `json:"userId"`
	UserName    string  `json:"userName"`
	SSOProvider *string `json:"ssoProvider,omitempty"`
	Reason      string  `json:"reason"`
}

// AccountOidcResponse represents custom OIDC Single Sign-On configuration for an account.
type AccountOidcResponse struct {
	Configured            bool                          `json:"configured"`
	AccountID             *string                       `json:"accountId,omitempty"`
	DiscoveryURL          *string                       `json:"discoveryUrl,omitempty"`
	ClientID              *string                       `json:"clientId,omitempty"`
	ClientSecretMasked    *string                       `json:"clientSecretMasked,omitempty"`
	EnforceSSO            bool                          `json:"enforceSso"`
	BreakGlassAdminsCount int                           `json:"breakGlassAdminsCount"`
	CanEnforceSSO         bool                          `json:"canEnforceSso"`
	NonCompliantUsers     []AccountOidcNonCompliantUser `json:"nonCompliantUsers,omitempty"`
	CreatedAt             *string                       `json:"createdAt,omitempty"`
	UpdatedAt             *string                       `json:"updatedAt,omitempty"`
}

// SaveAccountOidcRequest represents the request body for creating or updating custom OIDC SSO.
type SaveAccountOidcRequest struct {
	DiscoveryURL string `json:"discoveryUrl,omitempty"`
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
	EnforceSSO   *bool  `json:"enforceSso,omitempty"`
}

// AccountOidcDeleteResponse represents the response for deleting custom OIDC SSO configuration.
type AccountOidcDeleteResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// AccountOidcTestRequest represents the payload for testing an OIDC discovery URL.
type AccountOidcTestRequest struct {
	DiscoveryURL string `json:"discoveryUrl,omitempty"`
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
}

// AccountOidcTestResponse represents the response for testing an OIDC discovery URL.
type AccountOidcTestResponse struct {
	Success                 bool     `json:"success"`
	Valid                   bool     `json:"valid,omitempty"`
	ClientCredentialsTested *bool    `json:"clientCredentialsTested,omitempty"`
	ClientCredentialsValid  *bool    `json:"clientCredentialsValid,omitempty"`
	Issuer                  *string  `json:"issuer,omitempty"`
	AuthorizationEndpoint   *string  `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint           *string  `json:"tokenEndpoint,omitempty"`
	JwksURI                 *string  `json:"jwksUri,omitempty"`
	UserinfoEndpoint        *string  `json:"userinfoEndpoint,omitempty"`
	ScopesSupported         []string `json:"scopesSupported,omitempty"`
}
