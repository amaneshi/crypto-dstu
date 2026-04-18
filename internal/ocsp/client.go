package ocsp

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"io"
	"net/http"

	"crypto-dstu/internal/cert"
)

// Client performs OCSP requests over HTTP.
type Client struct {
	// HTTP is the underlying HTTP client. Nil means http.DefaultClient.
	HTTP *http.Client
	// URL overrides the OCSP URL. If empty, AIA from the certificate is used.
	URL string
}

// Check fetches and parses the OCSP status for cert issued by issuer.
// The OCSP URL is taken from c.URL if set, otherwise from the certificate's AIA extension.
func (c *Client) Check(subject, issuer *cert.Certificate) (*Response, error) {
	if subject == nil || issuer == nil {
		return nil, errors.New("ocsp: Check: nil certificate")
	}

	// Build CertID with Kupyna-256.
	cid, err := NewCertID(subject, issuer, oidKupyna256)
	if err != nil {
		// Fall back to GOST34311 if Kupyna fails (legacy UA PKI).
		cid, err = NewCertID(subject, issuer, oidGOST34311)
		if err != nil {
			return nil, errors.New("ocsp: Check: build CertID: " + err.Error())
		}
	}

	req, err := NewRequest([]*CertID{cid})
	if err != nil {
		return nil, errors.New("ocsp: Check: " + err.Error())
	}
	der, err := req.Marshal()
	if err != nil {
		return nil, errors.New("ocsp: Check: marshal request: " + err.Error())
	}

	// Determine URL.
	url := c.URL
	if url == "" {
		urls := AIAOCSPURLs(subject)
		if len(urls) == 0 {
			return nil, errors.New("ocsp: Check: no OCSP URL in certificate AIA and none configured")
		}
		url = urls[0]
	}

	// Post request.
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	//nolint:noctx // context not available at this call site
	httpResp, err := hc.Post(url, "application/ocsp-request", bytes.NewReader(der))
	if err != nil {
		return nil, errors.New("ocsp: Check: HTTP post: " + err.Error())
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, errors.New("ocsp: Check: read response: " + err.Error())
	}

	return ParseResponse(body)
}

// AIAOCSPURLs extracts OCSP responder URLs from the certificate's
// Authority Information Access extension (OID 1.3.6.1.5.5.7.1.1).
func AIAOCSPURLs(c *cert.Certificate) []string {
	return extractAIAOCSPURLs(c)
}

// oidAccessMethodOCSP is the accessMethod OID for OCSP in AIA (RFC 5280).
var oidAccessMethodOCSP = oidFromInts(1, 3, 6, 1, 5, 5, 7, 48, 1)

// oidAuthorityInfoAccess is the AIA extension OID.
var oidAuthorityInfoAccess = oidFromInts(1, 3, 6, 1, 5, 5, 7, 1, 1)

// Hash algorithm OIDs for CertID (mirrors oid package but avoids import cycle).
var (
	oidKupyna256 = oidFromInts(1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 1)
	oidGOST34311 = oidFromInts(1, 2, 804, 2, 1, 1, 1, 1, 2, 1)
)

func oidFromInts(arcs ...int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier(arcs)
}

// extractAIAOCSPURLs parses the AIA extension of a certificate and returns all OCSP URLs.
func extractAIAOCSPURLs(c *cert.Certificate) []string {
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidAuthorityInfoAccess) {
			continue
		}
		return parseAIAOCSPURLs(ext.Value)
	}
	return nil
}

// parseAIAOCSPURLs decodes an AIA extension value and returns OCSP URLs.
// AIA ::= SEQUENCE OF AccessDescription
// AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
// GeneralName uniformResourceIdentifier is [6] IMPLICIT IA5String.
func parseAIAOCSPURLs(der []byte) []string {
	type accessDesc struct {
		Method   asn1.ObjectIdentifier
		Location asn1.RawValue
	}

	// Unwrap outer SEQUENCE.
	var wrapper asn1.RawValue
	rest, err := asn1.Unmarshal(der, &wrapper)
	if err != nil || len(rest) != 0 || wrapper.Tag != asn1.TagSequence {
		return nil
	}

	var urls []string
	inner := wrapper.Bytes
	for len(inner) > 0 {
		var ad accessDesc
		inner, err = asn1.Unmarshal(inner, &ad)
		if err != nil {
			break
		}
		if ad.Method.Equal(oidAccessMethodOCSP) && ad.Location.Tag == 6 {
			urls = append(urls, string(ad.Location.Bytes))
		}
	}
	return urls
}
