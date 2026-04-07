package tsp

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"crypto-dstu/cert"
	"crypto-dstu/cms"
	"crypto-dstu/dstu4145"
	"crypto-dstu/kupyna"
)

// ---- helpers ----

var OIDKupyna256 = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 2, 2, 1}

func hashKupyna256(data []byte) []byte {
	h := kupyna.New256()
	h.Write(data)
	return h.Sum(nil)
}

func mustGenerateKey(t *testing.T) *dstu4145.PrivateKey {
	t.Helper()
	params := dstu4145.ParamsByName("DSTU_PB_257")
	require.NotNil(t, params)
	key, err := dstu4145.GenerateKey(params.Curve)
	require.NoError(t, err)
	return key
}

func makeCert(t *testing.T, key *dstu4145.PrivateKey) *cert.Certificate {
	t.Helper()
	issuerBytes := []byte{
		0x30, 0x13,
		0x31, 0x11,
		0x30, 0x0f,
		0x06, 0x03, 0x55, 0x04, 0x03,
		0x0c, 0x08, 0x54, 0x65, 0x73, 0x74, 0x54, 0x53, 0x41, 0x31, // "TestTSA1"
	}
	issuer := asn1.RawValue{FullBytes: issuerBytes}
	return &cert.Certificate{
		Raw:          []byte{0x30, 0x03, 0x01, 0x02, 0x03},
		SerialNumber: big.NewInt(99),
		Issuer:       issuer,
		Subject:      issuer,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		PublicKey:    key.Public(),
	}
}

// buildSampleToken builds a real CMS SignedData wrapping a DER-encoded TSTInfo,
// signed with the given key+cert. Returns the raw CMS ContentInfo DER bytes.
func buildSampleToken(
	t *testing.T,
	key *dstu4145.PrivateKey,
	tsaCert *cert.Certificate,
	hash []byte,
	nonce *big.Int,
) []byte {
	t.Helper()

	info := TSTInfo{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{1, 2, 3},
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDKupyna256},
			HashedMessage: hash,
		},
		SerialNumber: big.NewInt(1),
		GenTime:      time.Now().UTC().Truncate(time.Second),
		Nonce:        nonce,
	}
	tstInfoDER, err := asn1.Marshal(info)
	require.NoError(t, err)

	// Sign TSTInfo as CMS with OIDTSTInfo content type
	tokenDER, err := cms.Sign(tstInfoDER, key, tsaCert, cms.SignOptions{
		ContentType: OIDTSTInfo,
	})
	require.NoError(t, err)
	return tokenDER
}

// ---- Request tests ----

func TestNewRequest(t *testing.T) {
	hash := hashKupyna256([]byte("hello"))
	req, err := NewRequest(hash, OIDKupyna256)
	require.NoError(t, err)
	require.Equal(t, 1, req.Version)
	require.Equal(t, OIDKupyna256, req.MessageImprint.HashAlgorithm.Algorithm)
	require.Equal(t, hash, req.MessageImprint.HashedMessage)
	require.NotNil(t, req.Nonce)
	require.True(t, req.CertReq)
}

func TestNewRequestEmptyHash(t *testing.T) {
	_, err := NewRequest(nil, OIDKupyna256)
	require.Error(t, err)
}

func TestNewRequestEmptyOID(t *testing.T) {
	_, err := NewRequest([]byte{0x01}, nil)
	require.Error(t, err)
}

func TestRequestMarshal(t *testing.T) {
	hash := hashKupyna256([]byte("data"))
	req, err := NewRequest(hash, OIDKupyna256)
	require.NoError(t, err)

	der, err := req.Marshal()
	require.NoError(t, err)
	require.NotEmpty(t, der)

	// Round-trip: unmarshal back
	var req2 Request
	rest, err := asn1.Unmarshal(der, &req2)
	require.NoError(t, err)
	require.Empty(t, rest)
	require.Equal(t, 1, req2.Version)
	require.Equal(t, OIDKupyna256, req2.MessageImprint.HashAlgorithm.Algorithm)
	require.Equal(t, hash, req2.MessageImprint.HashedMessage)
	require.Equal(t, 0, req.Nonce.Cmp(req2.Nonce))
	require.True(t, req2.CertReq)
}

func TestRequestNonceUnique(t *testing.T) {
	hash := hashKupyna256([]byte("x"))
	r1, err := NewRequest(hash, OIDKupyna256)
	require.NoError(t, err)
	r2, err := NewRequest(hash, OIDKupyna256)
	require.NoError(t, err)
	// Two requests should (almost certainly) have different nonces
	require.NotEqual(t, 0, r1.Nonce.Cmp(r2.Nonce))
}

// ---- Response tests ----

func TestParseResponseGranted(t *testing.T) {
	// Build a minimal TimeStampResp with status=0 (granted) and no token
	respASN := struct {
		Status PKIStatusInfo
	}{Status: PKIStatusInfo{Status: StatusGranted}}
	der, err := asn1.Marshal(respASN)
	require.NoError(t, err)

	resp, err := ParseResponse(der)
	require.NoError(t, err)
	require.Equal(t, StatusGranted, resp.Status.Status)
	require.NoError(t, resp.Err())
}

func TestParseResponseRejected(t *testing.T) {
	respASN := struct {
		Status PKIStatusInfo
	}{Status: PKIStatusInfo{Status: StatusRejection}}
	der, err := asn1.Marshal(respASN)
	require.NoError(t, err)

	resp, err := ParseResponse(der)
	require.NoError(t, err)
	require.Error(t, resp.Err())
}

func TestParseResponseInvalidDER(t *testing.T) {
	_, err := ParseResponse([]byte{0x00, 0x01, 0x02})
	require.Error(t, err)
}

// ---- TSTInfo extraction tests ----

func TestParseTSTInfo(t *testing.T) {
	key := mustGenerateKey(t)
	tsaCert := makeCert(t, key)
	hash := hashKupyna256([]byte("document"))
	nonce := big.NewInt(12345)

	tokenDER := buildSampleToken(t, key, tsaCert, hash, nonce)

	info, err := ParseTSTInfo(tokenDER)
	require.NoError(t, err)
	require.Equal(t, 1, info.Version)
	require.Equal(t, hash, info.MessageImprint.HashedMessage)
	require.Equal(t, OIDKupyna256, info.MessageImprint.HashAlgorithm.Algorithm)
	require.Equal(t, 0, nonce.Cmp(info.Nonce))
	require.False(t, info.GenTime.IsZero())
}

func TestResponseTSTInfo(t *testing.T) {
	key := mustGenerateKey(t)
	tsaCert := makeCert(t, key)
	hash := hashKupyna256([]byte("doc"))
	nonce := big.NewInt(42)
	tokenDER := buildSampleToken(t, key, tsaCert, hash, nonce)

	// Wrap in a TimeStampResp
	tokenRaw := asn1.RawValue{FullBytes: tokenDER}
	respStruct := struct {
		Status         PKIStatusInfo
		TimeStampToken asn1.RawValue
	}{
		Status:         PKIStatusInfo{Status: StatusGranted},
		TimeStampToken: tokenRaw,
	}
	respDER, err := asn1.Marshal(respStruct)
	require.NoError(t, err)

	resp, err := ParseResponse(respDER)
	require.NoError(t, err)

	info, err := resp.TSTInfo()
	require.NoError(t, err)
	require.Equal(t, hash, info.MessageImprint.HashedMessage)
}

// ---- Verification tests ----

func TestVerifyTokenValid(t *testing.T) {
	key := mustGenerateKey(t)
	tsaCert := makeCert(t, key)
	hash := hashKupyna256([]byte("payload"))
	nonce := big.NewInt(777)
	tokenDER := buildSampleToken(t, key, tsaCert, hash, nonce)

	info, err := VerifyToken(tokenDER, hash, nonce, []*cert.Certificate{tsaCert})
	require.NoError(t, err)
	require.Equal(t, hash, info.MessageImprint.HashedMessage)
}

func TestVerifyTokenNoNonce(t *testing.T) {
	key := mustGenerateKey(t)
	tsaCert := makeCert(t, key)
	hash := hashKupyna256([]byte("payload"))
	tokenDER := buildSampleToken(t, key, tsaCert, hash, nil)

	// Passing nonce=nil means skip nonce check
	info, err := VerifyToken(tokenDER, hash, nil, []*cert.Certificate{tsaCert})
	require.NoError(t, err)
	require.Equal(t, hash, info.MessageImprint.HashedMessage)
}

func TestVerifyTokenWrongHash(t *testing.T) {
	key := mustGenerateKey(t)
	tsaCert := makeCert(t, key)
	hash := hashKupyna256([]byte("payload"))
	tokenDER := buildSampleToken(t, key, tsaCert, hash, nil)

	wrongHash := hashKupyna256([]byte("other"))
	_, err := VerifyToken(tokenDER, wrongHash, nil, []*cert.Certificate{tsaCert})
	require.Error(t, err)
	require.Contains(t, err.Error(), "message imprint mismatch")
}

func TestVerifyTokenNonceMismatch(t *testing.T) {
	key := mustGenerateKey(t)
	tsaCert := makeCert(t, key)
	hash := hashKupyna256([]byte("payload"))
	nonce := big.NewInt(100)
	tokenDER := buildSampleToken(t, key, tsaCert, hash, nonce)

	_, err := VerifyToken(tokenDER, hash, big.NewInt(999), []*cert.Certificate{tsaCert})
	require.Error(t, err)
	require.Contains(t, err.Error(), "nonce mismatch")
}

func TestVerifyTokenInvalidDER(t *testing.T) {
	_, err := VerifyToken([]byte{0x00, 0x01}, []byte{0x01}, nil, nil)
	require.Error(t, err)
}

// ---- HTTP Client tests ----

func TestClientSend(t *testing.T) {
	key := mustGenerateKey(t)
	tsaCert := makeCert(t, key)
	hash := hashKupyna256([]byte("test"))
	nonce := big.NewInt(55)
	tokenDER := buildSampleToken(t, key, tsaCert, hash, nonce)

	// Wrap in a valid TimeStampResp
	tokenRaw := asn1.RawValue{FullBytes: tokenDER}
	respStruct := struct {
		Status         PKIStatusInfo
		TimeStampToken asn1.RawValue
	}{
		Status:         PKIStatusInfo{Status: StatusGranted},
		TimeStampToken: tokenRaw,
	}
	respDER, err := asn1.Marshal(respStruct)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentTypeReply)
		w.WriteHeader(http.StatusOK)
		w.Write(respDER)
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	resp, err := client.Timestamp(hash, OIDKupyna256)
	require.NoError(t, err)
	require.NoError(t, resp.Err())

	info, err := resp.TSTInfo()
	require.NoError(t, err)
	require.True(t, bytes.Equal(info.MessageImprint.HashedMessage, hash))
}

func TestClientHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewClient(srv.URL)
	_, err := client.Timestamp(hashKupyna256([]byte("x")), OIDKupyna256)
	require.Error(t, err)
	require.Contains(t, err.Error(), "500")
}

func TestClientBadURL(t *testing.T) {
	client := NewClient("http://127.0.0.1:1") // nothing listening
	_, err := client.Timestamp(hashKupyna256([]byte("x")), OIDKupyna256)
	require.Error(t, err)
}
