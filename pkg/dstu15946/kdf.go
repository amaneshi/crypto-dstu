package dstu15946

import (
	"encoding/asn1"
	"errors"
	"hash"

	"crypto-dstu/pkg/dstu4145"
)

// OIDGost28147CfbWrap is the Ukrainian PKI OID for GOST 28147-89 CFB key-wrap.
// Used as the keyInfo.algorithm inside the DER-encoded SharedInfo structure.
var OIDGost28147CfbWrap = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 3}

// sharedInfoKeyInfo is the AlgorithmIdentifier embedded in SharedInfo.
type sharedInfoKeyInfo struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// sharedInfo is the DER-encoded structure prepended to ZZ before hashing
// to produce the KEK. Defined in the Ukrainian CMS (DSTSZI 2010) profile:
//
//	SharedInfo ::= SEQUENCE {
//	    keyInfo      AlgorithmIdentifier,
//	    entityInfo   [0] OCTET STRING OPTIONAL,  -- UKM bytes
//	    suppPubInfo  [2] OCTET STRING             -- key length in bits (BE uint32)
//	}
type sharedInfo struct {
	KeyInfo     sharedInfoKeyInfo
	EntityInfo  []byte `asn1:"optional,tag:0"`
	SuppPubInfo []byte `asn1:"tag:2"`
}

// sharedInfoDER builds the DER-encoded SharedInfo for a 256-bit KEK.
// suppPubInfo = 0x00000100 (= 256 bits in big-endian).
// ukm is placed in entityInfo if non-empty.
func sharedInfoDER(ukm []byte) ([]byte, error) {
	info := sharedInfo{
		KeyInfo:     sharedInfoKeyInfo{Algorithm: OIDGost28147CfbWrap},
		SuppPubInfo: []byte{0x00, 0x00, 0x01, 0x00},
	}
	if len(ukm) > 0 {
		info.EntityInfo = ukm
	}
	return asn1.Marshal(info)
}

// DeriveKey derives a KEK (key-encryption key) from a raw ECDH shared secret ZZ.
//
// This is the Ukrainian CMS-layer KDF used when wrapping content keys in
// CMS EnvelopedData (DSTSZI 2010 profile). It is NOT part of cryptonite's
// dstu4145_dh — it sits one layer above.
//
// Algorithm:
//  1. Strip a leading 0x00 byte from ZZ if present (field element normalisation)
//  2. kek_input = ZZ || \x00\x00\x00\x01 || DER(SharedInfo{keyInfo, ukm, 256-bits})
//  3. KEK = hashFn(kek_input)
//
// hashFn is typically gost34311.New (for GOST-based profiles) or kupyna.New256.
// ukm is the User Keying Material (random, typically 64 bytes); may be nil.
func DeriveKey(zz []byte, ukm []byte, hashFn func() hash.Hash) ([]byte, error) {
	if len(zz) == 0 {
		return nil, errors.New("dstu15946: empty shared secret")
	}

	// Strip leading zero byte (field element may have a leading zero after BE encoding)
	if zz[0] == 0 {
		zz = zz[1:]
	}

	salt, err := sharedInfoDER(ukm)
	if err != nil {
		return nil, errors.New("dstu15946: sharedInfoDER: " + err.Error())
	}

	h := hashFn()
	h.Write(zz)
	h.Write([]byte{0x00, 0x00, 0x00, 0x01})
	h.Write(salt)
	return h.Sum(nil), nil
}

// KeyAgreement is a convenience wrapper combining SharedSecret and DeriveKey.
//
// Both parties (sender and recipient) independently compute the same KEK:
//   - senderPriv:    sender's (ephemeral) private key
//   - recipientPub:  recipient's static public key
//   - ukm:           User Keying Material included in the CMS message (may be nil)
//   - hashFn:        hash constructor (e.g. gost34311.New or kupyna.New256)
func KeyAgreement(
	senderPriv *dstu4145.PrivateKey,
	recipientPub *dstu4145.PublicKey,
	ukm []byte,
	hashFn func() hash.Hash,
) ([]byte, error) {
	zz, err := SharedSecret(senderPriv, recipientPub)
	if err != nil {
		return nil, err
	}
	return DeriveKey(zz, ukm, hashFn)
}
