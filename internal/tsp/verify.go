package tsp

import (
	"bytes"
	"errors"
	"math/big"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/cms"
)

// VerifyToken verifies a TimeStampToken (DER-encoded CMS ContentInfo/SignedData).
//
// It checks:
//  1. CMS signature is valid (using the TSA certificate embedded in the token).
//  2. TSTInfo.MessageImprint.HashedMessage == originalHash.
//  3. If nonce != nil, TSTInfo.Nonce == nonce.
//
// caCerts may be nil to skip certificate chain verification.
// Returns the parsed and verified TSTInfo on success.
func VerifyToken(tokenDER []byte, originalHash []byte, nonce *big.Int, caCerts []*cert.Certificate) (*TSTInfo, error) {
	// 1. Parse and verify the CMS SignedData.
	msg, err := cms.ParseSigned(tokenDER)
	if err != nil {
		return nil, errors.New("tsp: parse token: " + err.Error())
	}
	if err = cms.VerifySigned(msg, nil, caCerts); err != nil {
		return nil, errors.New("tsp: verify token signature: " + err.Error())
	}

	// 2. Parse TSTInfo from the token.
	info, err := ParseTSTInfo(tokenDER)
	if err != nil {
		return nil, err
	}

	// 3. Verify MessageImprint hash.
	if !bytes.Equal(info.MessageImprint.HashedMessage, originalHash) {
		return nil, errors.New("tsp: message imprint mismatch")
	}

	// 4. Verify nonce if provided.
	if nonce != nil {
		if info.Nonce == nil || info.Nonce.Cmp(nonce) != 0 {
			return nil, errors.New("tsp: nonce mismatch")
		}
	}

	return info, nil
}
