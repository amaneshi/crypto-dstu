package tsp

import (
	"encoding/asn1"
	"errors"
)

// Response is an RFC 3161 TimeStampResp.
type Response struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// ParseResponse decodes a DER-encoded TimeStampResp.
func ParseResponse(der []byte) (*Response, error) {
	var resp Response
	if rest, err := asn1.Unmarshal(der, &resp); err != nil {
		return nil, errors.New("tsp: parse response: " + err.Error())
	} else if len(rest) > 0 {
		return nil, errors.New("tsp: parse response: trailing data")
	}
	return &resp, nil
}

// Err returns a non-nil error if the response status indicates failure.
func (r *Response) Err() error {
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
	if rest, err := asn1.Unmarshal(tstInfoBytes, &info); err != nil {
		return nil, errors.New("tsp: parse TSTInfo: " + err.Error())
	} else if len(rest) > 0 {
		return nil, errors.New("tsp: parse TSTInfo: trailing data")
	}
	return &info, nil
}

// extractTSTInfoBytes walks the CMS ContentInfo → SignedData → EContent
// to return the raw DER bytes of the TSTInfo SEQUENCE.
func extractTSTInfoBytes(tokenDER []byte) ([]byte, error) {
	// ContentInfo = SEQUENCE { OID, [0] EXPLICIT content }
	var ciSeq asn1.RawValue
	if _, err := asn1.Unmarshal(tokenDER, &ciSeq); err != nil {
		return nil, errors.New("tsp: parse ContentInfo: " + err.Error())
	}
	inner := ciSeq.Bytes

	// OID
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(inner, &oid)
	if err != nil {
		return nil, errors.New("tsp: parse ContentInfo OID: " + err.Error())
	}

	// [0] EXPLICIT { SignedData SEQUENCE }
	var ctx0 asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &ctx0); err != nil {
		return nil, errors.New("tsp: parse ContentInfo content: " + err.Error())
	}
	sdBytes := ctx0.Bytes

	// SignedData SEQUENCE — unwrap
	var sdSeq asn1.RawValue
	if _, err := asn1.Unmarshal(sdBytes, &sdSeq); err != nil {
		return nil, errors.New("tsp: parse SignedData: " + err.Error())
	}
	data := sdSeq.Bytes

	// Version
	var version int
	data, err = asn1.Unmarshal(data, &version)
	if err != nil {
		return nil, errors.New("tsp: parse SignedData version: " + err.Error())
	}

	// DigestAlgorithms SET
	var digAlgs asn1.RawValue
	data, err = asn1.Unmarshal(data, &digAlgs)
	if err != nil {
		return nil, errors.New("tsp: parse DigestAlgorithms: " + err.Error())
	}

	// EncapsulatedContentInfo SEQUENCE
	var eciSeq asn1.RawValue
	if _, err := asn1.Unmarshal(data, &eciSeq); err != nil {
		return nil, errors.New("tsp: parse ECI: " + err.Error())
	}
	eciInner := eciSeq.Bytes

	// EContentType OID
	var econtentType asn1.ObjectIdentifier
	eciRest, err := asn1.Unmarshal(eciInner, &econtentType)
	if err != nil {
		return nil, errors.New("tsp: parse EContentType: " + err.Error())
	}

	// [0] EXPLICIT { OCTET STRING { TSTInfo } }
	if len(eciRest) == 0 || eciRest[0] != 0xa0 {
		return nil, errors.New("tsp: ECI has no encapsulated content")
	}
	var ctx asn1.RawValue
	if _, err := asn1.Unmarshal(eciRest, &ctx); err != nil {
		return nil, errors.New("tsp: parse ECI content wrapper: " + err.Error())
	}
	var tstInfoDER []byte
	if _, err := asn1.Unmarshal(ctx.Bytes, &tstInfoDER); err != nil {
		return nil, errors.New("tsp: parse TSTInfo OCTET STRING: " + err.Error())
	}
	return tstInfoDER, nil
}
