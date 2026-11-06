package tsp

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"
	"math/big"
	"slices"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/pkg/gost34311"
	"github.com/amaneshi/crypto-dstu/pkg/kupyna"
)

var OIDTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}

// VerifiedToken establishes a token signature, exact imprint and current TSA path.
// It does not establish revocation or historical validity of a document signer.
type VerifiedToken struct {
	Info  *TSTInfo
	TSA   *cert.Certificate
	Chain []*cert.Certificate
}

// HashData computes an RFC 3161 imprint without DSTU signature byte reversal.
func HashData(data []byte, algorithm asn1.ObjectIdentifier) ([]byte, error) {
	var h hash.Hash
	switch {
	case algorithm.Equal(oid.GOST34311):
		h = gost34311.New()
	case algorithm.Equal(oid.Kupyna256):
		h = kupyna.New256()
	case algorithm.Equal(oid.Kupyna512):
		h = kupyna.New512()
	case algorithm.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}):
		h = sha256.New()
	case algorithm.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}):
		h = sha512.New()
	case algorithm.Equal(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}):
		h = sha1.New() // Legacy token verification.
	default:
		return nil, errors.New("tsp: unsupported imprint algorithm")
	}
	h.Write(data)
	return h.Sum(nil), nil
}

func validImprint(imprint MessageImprint) error {
	digest, err := HashData(nil, imprint.HashAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	parameters := imprint.HashAlgorithm.Parameters.FullBytes
	if len(parameters) > 0 && !bytes.Equal(parameters, []byte{5, 0}) {
		return errors.New("tsp: unsupported imprint parameters")
	}
	if len(imprint.HashedMessage) != len(digest) {
		return errors.New("tsp: wrong imprint length")
	}
	return nil
}

// VerifyToken preserves the hash-only API. Call VerifyImprint to additionally
// bind the expected algorithm, or VerifySignatureTimestamp for CAdES-T binding.
func VerifyToken(tokenDER, originalHash []byte, nonce *big.Int, roots []*cert.Certificate) (*TSTInfo, error) {
	info, err := ParseTSTInfo(tokenDER)
	if err != nil {
		return nil, err
	}
	expected := info.MessageImprint
	expected.HashedMessage = originalHash
	verified, err := VerifyImprint(tokenDER, expected, nonce, roots, time.Now())
	if err != nil {
		return nil, err
	}
	return verified.Info, nil
}

// VerifyImprint requires one TSA signer, ESS binding and an exclusive critical
// timestamping EKU. The path must be valid now; the TSA must also cover genTime.
func VerifyImprint(tokenDER []byte, expected MessageImprint, nonce *big.Int, roots []*cert.Certificate, now time.Time, discovery ...*cert.Certificate) (*VerifiedToken, error) {
	if len(roots) == 0 {
		return nil, errors.New("tsp: trusted TSA certificates are required")
	}
	info, msg, tsa, err := verifyTokenContent(tokenDER, expected, nonce, now, slices.Concat(discovery, roots))
	if err != nil {
		return nil, err
	}
	chain, err := cert.BuildCertChainForUsageAt(tsa, roots, msg.Certificates, now, OIDTimeStamping)
	if err != nil {
		return nil, err
	}
	for _, c := range chain {
		if info.GenTime.Before(c.NotBefore) || info.GenTime.After(c.NotAfter) {
			return nil, errors.New("tsp: TSA path does not cover genTime")
		}
	}
	return &VerifiedToken{Info: info, TSA: tsa, Chain: chain}, nil
}

// VerifyImprintUnanchored performs every VerifyImprint check except building a
// path to a trusted root: imprint, nonce, TSTInfo fields, one ESS-bound TSA
// signer with a valid signature, and an exclusive timestamping EKU on a TSA
// certificate that covers genTime. It does NOT establish that the TSA is
// trusted; the returned Chain is nil. Use it only where trust in the TSA is
// decided elsewhere (for example by the relying party that verifies the document).
func VerifyImprintUnanchored(tokenDER []byte, expected MessageImprint, nonce *big.Int, now time.Time, discovery ...*cert.Certificate) (*VerifiedToken, error) {
	info, _, tsa, err := verifyTokenContent(tokenDER, expected, nonce, now, discovery)
	if err != nil {
		return nil, err
	}
	return &VerifiedToken{Info: info, TSA: tsa}, nil
}

// verifyTokenContent holds the root-independent checks shared by VerifyImprint
// and VerifyImprintUnanchored. extra certificates only help locate the TSA signer.
func verifyTokenContent(tokenDER []byte, expected MessageImprint, nonce *big.Int, now time.Time, extra []*cert.Certificate) (*TSTInfo, *cms.SignedMessage, *cert.Certificate, error) {
	if err := validImprint(expected); err != nil {
		return nil, nil, nil, err
	}
	info, err := ParseTSTInfo(tokenDER)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := validImprint(info.MessageImprint); err != nil {
		return nil, nil, nil, err
	}
	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(expected.HashAlgorithm.Algorithm) || !bytes.Equal(info.MessageImprint.HashedMessage, expected.HashedMessage) {
		return nil, nil, nil, errors.New("tsp: message imprint mismatch")
	}
	if nonce != nil && (info.Nonce == nil || info.Nonce.Cmp(nonce) != 0) {
		return nil, nil, nil, errors.New("tsp: nonce mismatch")
	}
	if info.Version != 1 || len(info.Policy) == 0 || info.SerialNumber == nil || info.SerialNumber.Sign() <= 0 || info.GenTime.IsZero() || info.GenTime.After(now.Add(5*time.Minute)) || info.Accuracy.Seconds < 0 || info.Accuracy.Millis < 0 || info.Accuracy.Millis > 999 || info.Accuracy.Micros < 0 || info.Accuracy.Micros > 999 || info.Nonce != nil && info.Nonce.Sign() < 0 {
		return nil, nil, nil, errors.New("tsp: invalid TSTInfo fields or future time")
	}
	if len(info.Extensions.FullBytes) > 0 {
		wrapped, err := asn1.Marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: info.Extensions.Bytes})
		if err != nil {
			return nil, nil, nil, err
		}
		var extensions []pkix.Extension
		if rest, err := asn1.Unmarshal(wrapped, &extensions); err != nil || len(rest) != 0 {
			return nil, nil, nil, errors.New("tsp: malformed extensions")
		}
		seen := map[string]bool{}
		for _, e := range extensions {
			if seen[e.Id.String()] || e.Critical {
				return nil, nil, nil, errors.New("tsp: duplicate or unsupported critical extension")
			}
			seen[e.Id.String()] = true
		}
	}
	msg, err := cms.ParseSigned(tokenDER)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(msg.Signers) != 1 || !msg.HasSigningCertificate(0) {
		return nil, nil, nil, errors.New("tsp: exactly one ESS-bound TSA signer is required")
	}
	msg.Certificates = append(msg.Certificates, extra...)
	if err := cms.VerifySigned(msg, nil, nil); err != nil {
		return nil, nil, nil, err
	}
	tsa := msg.Signers[0].Certificate
	if err := checkTSA(tsa, info); err != nil {
		return nil, nil, nil, err
	}
	return info, msg, tsa, nil
}

func checkTSA(tsa *cert.Certificate, info *TSTInfo) error {
	if tsa == nil || info.GenTime.Before(tsa.NotBefore) || info.GenTime.After(tsa.NotAfter) {
		return errors.New("tsp: TSA certificate does not cover genTime")
	}
	found := false
	for _, e := range tsa.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
			var uses []asn1.ObjectIdentifier
			if rest, err := asn1.Unmarshal(e.Value, &uses); err != nil || len(rest) != 0 || !e.Critical || len(uses) != 1 || !uses[0].Equal(OIDTimeStamping) || found {
				return errors.New("tsp: exclusive critical timestamping EKU is required")
			}
			found = true
		}
	}
	if !found {
		return errors.New("tsp: timestamping EKU is required")
	}
	if len(info.TSA.FullBytes) > 0 {
		var name asn1.RawValue
		if rest, err := asn1.Unmarshal(info.TSA.Bytes, &name); err != nil || len(rest) != 0 || name.Class != 2 {
			return errors.New("tsp: malformed TSA name")
		}
		match := name.Tag == 4 && bytes.Equal(name.Bytes, tsa.Subject.FullBytes)
		for _, e := range tsa.Extensions {
			if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
				var names []asn1.RawValue
				if rest, err := asn1.Unmarshal(e.Value, &names); err != nil || len(rest) != 0 {
					return errors.New("tsp: malformed TSA subjectAltName")
				}
				for _, n := range names {
					match = match || bytes.Equal(n.FullBytes, name.FullBytes)
				}
			}
		}
		if !match {
			return errors.New("tsp: TSA name does not match signer")
		}
	}
	return nil
}

// VerifySignatureTimestamp binds a token's imprint to the exact CMS signature
// value octets, not the document content or an ASN.1 wrapper around the signature.
func VerifySignatureTimestamp(tokenDER, signature []byte, roots []*cert.Certificate, now time.Time, discovery ...*cert.Certificate) (*VerifiedToken, error) {
	info, err := ParseTSTInfo(tokenDER)
	if err != nil {
		return nil, err
	}
	expected := info.MessageImprint
	expected.HashedMessage, err = HashData(signature, expected.HashAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	return VerifyImprint(tokenDER, expected, nil, roots, now, discovery...)
}

// VerifyResponse binds a successful protocol response to the original request.
// A requested policy and certificate inclusion are enforced as well as nonce
// and the complete algorithm/imprint pair. Discovery never becomes trust.
func VerifyResponse(response *Response, request *Request, roots []*cert.Certificate, now time.Time, discovery ...*cert.Certificate) (*VerifiedToken, error) {
	return verifyResponse(response, request, func(token []byte) (*VerifiedToken, error) {
		return VerifyImprint(token, request.MessageImprint, request.Nonce, roots, now, discovery...)
	})
}

// VerifyResponseUnanchored is VerifyResponse without the trusted-root path
// (see VerifyImprintUnanchored). The returned Chain is nil.
func VerifyResponseUnanchored(response *Response, request *Request, now time.Time, discovery ...*cert.Certificate) (*VerifiedToken, error) {
	return verifyResponse(response, request, func(token []byte) (*VerifiedToken, error) {
		return VerifyImprintUnanchored(token, request.MessageImprint, request.Nonce, now, discovery...)
	})
}

func verifyResponse(response *Response, request *Request, verify func(token []byte) (*VerifiedToken, error)) (*VerifiedToken, error) {
	if request == nil || request.Version != 1 {
		return nil, errors.New("tsp: original v1 request is required")
	}
	token, err := response.Token()
	if err != nil {
		return nil, err
	}
	verified, err := verify(token)
	if err != nil {
		return nil, err
	}
	if len(request.ReqPolicy) > 0 && !request.ReqPolicy.Equal(verified.Info.Policy) {
		return nil, errors.New("tsp: requested policy mismatch")
	}
	if request.CertReq {
		message, err := cms.ParseSigned(token)
		if err != nil {
			return nil, err
		}
		found := false
		for _, c := range message.Certificates {
			found = found || bytes.Equal(c.Raw, verified.TSA.Raw)
		}
		if !found {
			return nil, errors.New("tsp: requested TSA certificate is missing from token")
		}
	}
	return verified, nil
}
