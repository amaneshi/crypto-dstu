package cms

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/testpki"
	czo "github.com/amaneshi/crypto-dstu/testdata/czo"
	"github.com/stretchr/testify/require"
)

func FuzzParseAndVerifySigned(f *testing.F) {
	certificate, key := testpki.Issue(f, "Disposable CMS fuzz signer", nil, nil, nil)
	content := []byte("CMS fuzz content\x00\xff")
	for _, digest := range []asn1.ObjectIdentifier{oid.GOST34311, oid.Kupyna256, oid.Kupyna512} {
		for _, detached := range []bool{false, true} {
			seed, err := Sign(content, key, certificate, SignOptions{Detached: detached, DigestAlgorithm: digest})
			require.NoError(f, err)
			message, err := VerifySignedRaw(seed, content, nil)
			require.NoError(f, err)
			require.True(f, message.Signers[0].Valid)
			f.Add(seed, content)
		}
	}
	for _, profile := range []string{"DSTU", "DSTU-7564"} {
		seed, err := os.ReadFile(czo.Path("cades/" + profile + "/enveloped/CAdES-BES/test.txt.p7s"))
		require.NoError(f, err)
		f.Add(seed, []byte{})
	}
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x30, 0}, []byte{})
	other, otherKey := testpki.Issue(f, "Second disposable CMS signer", nil, nil, nil)
	first, err := Sign(content, key, certificate, SignOptions{})
	require.NoError(f, err)
	second, err := Sign(content, otherKey, other, SignOptions{})
	require.NoError(f, err)
	firstMessage, err := ParseSigned(first)
	require.NoError(f, err)
	secondMessage, err := ParseSigned(second)
	require.NoError(f, err)
	signers := append(firstMessage.rawSigners, secondMessage.rawSigners...)
	for _, corruptSecond := range []bool{false, true} {
		if corruptSecond {
			signers[1].Signature[0] ^= 1
		}
		inner, err := marshalSignedData(1, oid.GOST34311,
			EncapsulatedContentInfo{EContentType: OIDData, EContent: content}, signers, certificate.Raw, other.Raw)
		require.NoError(f, err)
		typeDER, err := asn1.Marshal(OIDSignedData)
		require.NoError(f, err)
		seed := marshalSEQ(append(typeDER, marshalEXPLICIT(0, inner)...))
		parsed, err := ParseSigned(seed)
		require.NoError(f, err)
		if corruptSecond {
			require.Error(f, VerifySigned(parsed, nil, nil))
		} else {
			require.NoError(f, VerifySigned(parsed, nil, nil))
		}
		f.Add(seed, content)
	}
	// Retained native samples anchor the newly supported ONB Kupyna profiles.
	// Preserve both the rejected PB-tagged originals and explicit ONB test forms.
	for _, degree := range []int{173, 431} {
		data, err := os.ReadFile(fmt.Sprintf("testdata/iit-onb-kupyna/DSTU_ONB_%d.json", degree))
		require.NoError(f, err)
		var fixture struct {
			Content []byte
			Samples []struct {
				Bits      int
				Signature []byte
			}
		}
		require.NoError(f, json.Unmarshal(data, &fixture))
		for _, sample := range fixture.Samples {
			pb, onb := oid.DSTU4145WithKupyna256, oid.DSTU4145ONBWithKupyna256
			if sample.Bits == 512 {
				pb, onb = oid.DSTU4145WithKupyna512, oid.DSTU4145ONBWithKupyna512
			}
			pbDER, err := asn1.Marshal(pb)
			require.NoError(f, err)
			onbDER, err := asn1.Marshal(onb)
			require.NoError(f, err)
			corrected := bytes.Replace(sample.Signature, pbDER, onbDER, 1)
			_, err = VerifySignedRaw(corrected, fixture.Content, nil)
			require.NoError(f, err)
			f.Add(sample.Signature, fixture.Content)
			f.Add(corrected, fixture.Content)
		}
	}
	f.Fuzz(func(t *testing.T, data, detached []byte) {
		if len(data) > 64<<10 || len(detached) > 64<<10 {
			return
		}
		original, originalDetached := bytes.Clone(data), bytes.Clone(detached)
		message, err := ParseSigned(data)
		require.Equal(t, original, data)
		if err != nil {
			require.Nil(t, message)
			return
		}
		for _, signer := range message.Signers {
			require.False(t, signer.Valid, "parsing alone authenticated a signer")
		}
		withJunk, err := ParseSigned(append(bytes.Clone(data), 0))
		require.Error(t, err)
		require.Nil(t, withJunk)
		content := message.Content
		if content == nil {
			content = detached
		}
		// Nil roots request mathematical checks only; these fixtures establish
		// no identity trust and trigger no certificate/timestamp network calls.
		if VerifySigned(message, content, nil) == nil {
			require.NotEmpty(t, message.Signers)
			for _, signer := range message.Signers {
				require.True(t, signer.Valid)
				require.NoError(t, signer.Error)
			}
			require.Error(t, VerifySigned(message, append(bytes.Clone(content), 1), nil))
			for _, signer := range message.Signers {
				require.False(t, signer.Valid, "failed reverification retained an authenticated flag")
			}
		}
		require.Equal(t, original, data, "verification changed the caller's DER")
		require.Equal(t, originalDetached, detached, "verification changed detached content")
	})
}
