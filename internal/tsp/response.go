package tsp

import (
	"bytes"
	"encoding/asn1"
	"errors"

	"crypto-dstu/internal/cms"
)

// Response is an RFC 3161 TimeStampResp.
type Response struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// ParseResponse decodes a DER-encoded TimeStampResp.
func ParseResponse(der []byte) (*Response, error) {
	if len(der) == 0 || len(der) > 4<<20 {
		return nil, errors.New("tsp: invalid response size")
	}
	var resp Response
	if rest, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, errors.New("tsp: parse response: " + err.Error())
	} else if len(rest) > 0 {
		return nil, errors.New("tsp: parse response: trailing data")
	}
	hasToken := len(resp.TimeStampToken.FullBytes) > 0
	if resp.Status.Status < 0 || resp.Status.Status > 5 || ((resp.Status.Status == 0 || resp.Status.Status == 1) != hasToken) {
		return nil, errors.New("tsp: inconsistent response status/token")
	}
	return &resp, nil
}

// Err returns a non-nil error if the response status indicates failure.
func (r *Response) Err() error {
	if r == nil {
		return errors.New("tsp: missing response")
	}
	switch r.Status.Status {
	case StatusGranted, StatusGrantedWithMods:
		return nil
	default:
		msg := "tsp: request rejected"
		if len(r.Status.StatusString) > 0 {
			msg += ": " + r.Status.StatusString[0]
		}
		return errors.New(msg)
	}
}

// Token returns the raw DER bytes of the TimeStampToken (CMS ContentInfo).
func (r *Response) Token() ([]byte, error) {
	if err := r.Err(); err != nil {
		return nil, err
	}
	if len(r.TimeStampToken.FullBytes) == 0 && len(r.TimeStampToken.Bytes) == 0 {
		return nil, errors.New("tsp: response has no timestamp token")
	}
	if len(r.TimeStampToken.FullBytes) > 0 {
		return r.TimeStampToken.FullBytes, nil
	}
	// Re-encode from raw fields if FullBytes not populated
	b, err := asn1.Marshal(r.TimeStampToken)
	if err != nil {
		return nil, errors.New("tsp: re-encode token: " + err.Error())
	}
	return b, nil
}

// TSTInfo parses and returns the TSTInfo from inside the TimeStampToken.
// The token is a CMS SignedData whose encapsulated content is a TSTInfo.
func (r *Response) TSTInfo() (*TSTInfo, error) {
	tokenDER, err := r.Token()
	if err != nil {
		return nil, err
	}
	return ParseTSTInfo(tokenDER)
}

// ParseTSTInfo extracts and parses the TSTInfo from a raw TimeStampToken DER
// (i.e. a CMS ContentInfo wrapping SignedData whose eContent is TSTInfo).
func ParseTSTInfo(tokenDER []byte) (*TSTInfo, error) {
	tstInfoBytes, err := extractTSTInfoBytes(tokenDER)
	if err != nil {
		return nil, err
	}
	var info TSTInfo
	var rest []byte
	rest, err = asn1.Unmarshal(tstInfoBytes, &info)
	if err != nil {
		return nil, errors.New("tsp: parse TSTInfo: " + err.Error())
	}
	if len(rest) > 0 {
		return nil, errors.New("tsp: parse TSTInfo: trailing data")
	}
	canonical, err := asn1.Marshal(info)
	if err != nil || !bytes.Equal(canonical, tstInfoBytes) {
		return nil, errors.New("tsp: noncanonical TSTInfo fields")
	}
	return &info, nil
}

// extractTSTInfoBytes walks the CMS ContentInfo → SignedData → EContent
// to return the raw DER bytes of the TSTInfo SEQUENCE.
func extractTSTInfoBytes(tokenDER []byte) ([]byte, error) {
	if len(tokenDER) == 0 || len(tokenDER) > 4<<20 {
		return nil, errors.New("tsp: invalid token size")
	}
	msg, err := cms.ParseSigned(tokenDER)
	if err != nil {
		return nil, err
	}
	if !msg.ContentType().Equal(OIDTSTInfo) || msg.Content == nil {
		return nil, errors.New("tsp: token must encapsulate id-ct-TSTInfo")
	}
	return msg.Content, nil
}
