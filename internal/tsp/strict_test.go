package tsp_test

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	"github.com/amaneshi/crypto-dstu/internal/testtimestamp"
	"github.com/amaneshi/crypto-dstu/internal/tsp"
	"github.com/stretchr/testify/require"
)

func TestStrictTimestampAcceptance(t *testing.T) {
	root, key := testpki.Issue(t, "TSA root", nil, nil, testpki.CAExtensions(t))
	tsa, tsaKey := testpki.Issue(t, "TSA", root, key, testtimestamp.Extensions(t))
	signature := []byte("exact CMS signature octets")
	good := testtimestamp.Token(t, signature, tsa, tsaKey, nil)
	verified, err := tsp.VerifySignatureTimestamp(good, signature, []*cert.Certificate{root}, time.Now())
	require.NoError(t, err)
	require.Len(t, verified.Chain, 2)
	for _, tc := range []struct {
		name   string
		change func(*tsp.TSTInfo)
	}{
		{"wrong version", func(i *tsp.TSTInfo) { i.Version = 2 }},
		{"zero serial", func(i *tsp.TSTInfo) { i.SerialNumber = big.NewInt(0) }},
		{"future", func(i *tsp.TSTInfo) { i.GenTime = time.Now().Add(time.Hour) }},
		{"outside TSA validity", func(i *tsp.TSTInfo) { i.GenTime = tsa.NotBefore.Add(-time.Hour) }},
		{"bad accuracy", func(i *tsp.TSTInfo) { i.Accuracy.Millis = 1000 }},
		{"negative nonce", func(i *tsp.TSTInfo) { i.Nonce = big.NewInt(-1) }},
		{"wrong imprint length", func(i *tsp.TSTInfo) { i.MessageImprint.HashedMessage = []byte{1} }},
		{"unsupported imprint", func(i *tsp.TSTInfo) { i.MessageImprint.HashAlgorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3} }},
		{"unsupported imprint parameters", func(i *tsp.TSTInfo) {
			i.MessageImprint.HashAlgorithm.Parameters = asn1.RawValue{FullBytes: []byte{2, 1, 1}}
		}},
		{"wrong TSA name", func(i *tsp.TSTInfo) {
			name, _ := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 4, IsCompound: true, Bytes: root.Subject.FullBytes})
			i.TSA = asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: name}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := testtimestamp.Token(t, signature, tsa, tsaKey, tc.change)
			_, err := tsp.VerifySignatureTimestamp(token, signature, []*cert.Certificate{root}, time.Now())
			require.Error(t, err)
		})
	}
	_, err = tsp.VerifySignatureTimestamp(good, []byte("other signature"), []*cert.Certificate{root}, time.Now())
	require.Error(t, err)
	imprint, _ := tsp.HashData(signature, oid.GOST34311)
	expected := tsp.MessageImprint{HashAlgorithm: tsp.AlgorithmIdentifier{Algorithm: oid.Kupyna256}, HashedMessage: imprint}
	_, err = tsp.VerifyImprint(good, expected, nil, []*cert.Certificate{root}, time.Now())
	require.Error(t, err, "equal-length digest bytes do not substitute for the expected algorithm")
	_, err = tsp.VerifySignatureTimestamp(good, signature, nil, time.Now())
	require.Error(t, err)
	altered := bytes.Clone(good)
	altered[len(altered)-1] ^= 1
	_, err = tsp.VerifySignatureTimestamp(altered, signature, []*cert.Certificate{root}, time.Now())
	require.Error(t, err)
	info, _ := tsp.ParseTSTInfo(good)
	encoded, err := asn1.Marshal(*info)
	require.NoError(t, err)
	ordinary, err := cms.Sign(encoded, tsaKey, tsa, cms.SignOptions{})
	require.NoError(t, err)
	_, err = tsp.VerifySignatureTimestamp(ordinary, signature, []*cert.Certificate{root}, time.Now())
	require.Error(t, err)
	for _, tc := range []struct {
		name string
		exts []pkix.Extension
	}{
		{"missing", nil},
		{"noncritical", func() []pkix.Extension { x := testtimestamp.Extensions(t); x[0].Critical = false; return x }()},
		{"mixed purpose", func() []pkix.Extension {
			x := testtimestamp.Extensions(t)
			x[0].Value, _ = asn1.Marshal([]asn1.ObjectIdentifier{tsp.OIDTimeStamping, {1, 3, 6, 1, 5, 5, 7, 3, 9}})
			return x
		}()},
		{"duplicate", append(testtimestamp.Extensions(t), testtimestamp.Extensions(t)...)},
	} {
		t.Run("EKU "+tc.name, func(t *testing.T) {
			bad, k := testpki.Issue(t, "bad TSA", root, key, tc.exts)
			token := testtimestamp.Token(t, signature, bad, k, nil)
			_, err := tsp.VerifySignatureTimestamp(token, signature, []*cert.Certificate{root}, time.Now())
			require.Error(t, err)
		})
	}
}

func TestProtocolResponseBindsRequest(t *testing.T) {
	root, key := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	tsa, tsaKey := testpki.Issue(t, "TSA", root, key, testtimestamp.Extensions(t))
	signature := []byte("signature")
	token := testtimestamp.Token(t, signature, tsa, tsaKey, func(i *tsp.TSTInfo) { i.Nonce = big.NewInt(17) })
	response := &tsp.Response{Status: tsp.PKIStatusInfo{Status: tsp.StatusGranted}, TimeStampToken: asn1.RawValue{FullBytes: token}}
	imprint, _ := tsp.HashData(signature, oid.GOST34311)
	request := &tsp.Request{Version: 1, CertReq: true, Nonce: big.NewInt(17), MessageImprint: tsp.MessageImprint{HashAlgorithm: tsp.AlgorithmIdentifier{Algorithm: oid.GOST34311}, HashedMessage: imprint}}
	_, err := tsp.VerifyResponse(response, request, []*cert.Certificate{root}, time.Now())
	require.NoError(t, err)
	request.ReqPolicy = asn1.ObjectIdentifier{1, 2, 9}
	_, err = tsp.VerifyResponse(response, request, []*cert.Certificate{root}, time.Now())
	require.ErrorContains(t, err, "policy mismatch")
	request.ReqPolicy = nil
	request.Nonce = big.NewInt(18)
	_, err = tsp.VerifyResponse(response, request, []*cert.Certificate{root}, time.Now())
	require.ErrorContains(t, err, "nonce mismatch")
	request.Nonce = big.NewInt(17)
	request.Version = 2
	_, err = tsp.VerifyResponse(response, request, []*cert.Certificate{root}, time.Now())
	require.Error(t, err)
}

func TestRequestCertificateInclusion(t *testing.T) {
	root, key := testpki.Issue(t, "root", nil, nil, testpki.CAExtensions(t))
	tsa, tsaKey := testpki.Issue(t, "TSA", root, key, testtimestamp.Extensions(t))
	token := testtimestamp.Token(t, []byte("signature"), tsa, tsaKey, nil)
	var ci asn1.RawValue
	_, err := asn1.Unmarshal(token, &ci)
	require.NoError(t, err)
	var typ asn1.ObjectIdentifier
	remaining, err := asn1.Unmarshal(ci.Bytes, &typ)
	require.NoError(t, err)
	var ctx, sd asn1.RawValue
	_, err = asn1.Unmarshal(remaining, &ctx)
	require.NoError(t, err)
	_, err = asn1.Unmarshal(ctx.Bytes, &sd)
	require.NoError(t, err)
	remaining = sd.Bytes
	var fields []byte
	for len(remaining) > 0 {
		var value asn1.RawValue
		remaining, err = asn1.Unmarshal(remaining, &value)
		require.NoError(t, err)
		if value.Class == 2 && value.Tag == 0 {
			continue
		}
		fields = append(fields, value.FullBytes...)
	}
	sdDER, err := asn1.Marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: fields})
	require.NoError(t, err)
	ctxDER, err := asn1.Marshal(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sdDER})
	require.NoError(t, err)
	typDER, err := asn1.Marshal(typ)
	require.NoError(t, err)
	stripped, err := asn1.Marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: append(typDER, ctxDER...)})
	require.NoError(t, err)
	info, err := tsp.ParseTSTInfo(stripped)
	require.NoError(t, err)
	request := &tsp.Request{Version: 1, CertReq: true, MessageImprint: info.MessageImprint}
	response := &tsp.Response{Status: tsp.PKIStatusInfo{Status: tsp.StatusGranted}, TimeStampToken: asn1.RawValue{FullBytes: stripped}}
	_, err = tsp.VerifyResponse(response, request, []*cert.Certificate{root}, time.Now(), tsa)
	require.ErrorContains(t, err, "requested TSA certificate is missing")
	request.CertReq = false
	_, err = tsp.VerifyResponse(response, request, []*cert.Certificate{root}, time.Now(), tsa)
	require.NoError(t, err)
}
