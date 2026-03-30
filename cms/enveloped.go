package cms

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"

	"crypto-dstu/cert"
	"crypto-dstu/dstu15946"
	"crypto-dstu/dstu4145"
	"crypto-dstu/ec"
	"crypto-dstu/gf2m"
	"crypto-dstu/gost28147"
	"crypto-dstu/gost34311"
)

// OIDs for EnvelopedData algorithms.
var (
	OIDGost28147CFB  = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 2}
	OIDGost28147Wrap = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 3}
	OIDDSTU4145DH    = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 2, 1}
)

// EncryptedContentInfo holds the symmetrically encrypted payload.
type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm encContentAlgID
	EncryptedContent           []byte `asn1:"optional,implicit,tag:0"`
}

type encContentAlgID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters gost28147Params
}

type gost28147Params struct {
	IV   []byte
	SBox asn1.ObjectIdentifier `asn1:"optional"`
}

// RecipientEncryptedKey holds a wrapped CEK for one recipient.
type RecipientEncryptedKey struct {
	RID          recipientIdentifier
	EncryptedKey []byte
}

type recipientIdentifier struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// KeyAgreeRecipientInfo is RFC 5652 §6.2.2 for ECDH key agreement.
type KeyAgreeRecipientInfo struct {
	Version                int
	Originator             asn1.RawValue `asn1:"explicit,tag:0"`
	UKM                    []byte        `asn1:"explicit,optional,tag:1"`
	KeyEncryptionAlgorithm AlgorithmIdentifier
	RecipientEncryptedKeys []RecipientEncryptedKey `asn1:"sequence"`
}

// rawEnvelopedData is the ASN.1 structure for EnvelopedData.
type rawEnvelopedData struct {
	Version              int
	OriginatorInfo       asn1.RawValue `asn1:"optional,implicit,tag:0"`
	RecipientInfos       asn1.RawValue `asn1:"set"` // SET OF RecipientInfo (context-tagged)
	EncryptedContentInfo EncryptedContentInfo
	UnprotectedAttrs     asn1.RawValue `asn1:"optional,implicit,tag:1"`
}

// EncryptedMessage is the result of parsing an EnvelopedData.
type EncryptedMessage struct {
	Algorithm  asn1.ObjectIdentifier
	IV         []byte
	CipherText []byte
	Recipients []parsedRecipient
}

type parsedRecipient struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
	OriginatorPK []byte // compressed/raw public key bytes from originator
	UKM          []byte
	WrappedCEK   []byte
}

// Encrypt encrypts content for one or more recipients using ECDH + GOST28147 CFB.
// senderKey is the sender's ephemeral or static private key.
// Returns DER-encoded ContentInfo wrapping EnvelopedData.
func Encrypt(content []byte, recipients []*cert.Certificate, senderKey *dstu4145.PrivateKey) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("cms: Encrypt: no recipients")
	}

	// 1. Generate random CEK (32 bytes) and IV (8 bytes)
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		return nil, errors.New("cms: generate CEK: " + err.Error())
	}
	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		return nil, errors.New("cms: generate IV: " + err.Error())
	}

	// 2. Encrypt content with GOST CFB
	ciphertext, err := gost28147.EncryptCFB(cek, iv, content)
	if err != nil {
		return nil, errors.New("cms: encrypt content: " + err.Error())
	}

	// 3. Encode sender's public key (uncompressed BE X||Y) for embedding in originator field
	senderPub := senderKey.Public()
	byteLen := (senderKey.Curve.M + 7) / 8
	senderPKBytes := encodePublicKeyUncompressed(senderPub, byteLen)

	// 4. Generate random UKM (64 bytes)
	ukm := make([]byte, 64)
	if _, err := rand.Read(ukm); err != nil {
		return nil, errors.New("cms: generate UKM: " + err.Error())
	}

	// 5. For each recipient: ECDH → DeriveKey → WrapKey
	var recipiInfosDER []byte
	for _, rcpt := range recipients {
		if rcpt.PublicKey == nil {
			return nil, errors.New("cms: recipient has no public key")
		}

		kek, err := dstu15946.KeyAgreement(senderKey, rcpt.PublicKey, ukm, gost34311.New)
		if err != nil {
			return nil, errors.New("cms: KeyAgreement: " + err.Error())
		}
		if len(kek) > 32 {
			kek = kek[:32]
		}

		// Random wrap IV (8 bytes)
		wrapIV := make([]byte, 8)
		if _, err := rand.Read(wrapIV); err != nil {
			return nil, errors.New("cms: generate wrapIV: " + err.Error())
		}

		wrappedCEK, err := gost28147.WrapKey(kek, cek, wrapIV)
		if err != nil {
			return nil, errors.New("cms: WrapKey: " + err.Error())
		}

		// Build RID (IssuerAndSerialNumber) manually to avoid asn1.RawValue length bug
		ridDER, err := marshalIssuerAndSerial(rcpt.Issuer, rcpt.SerialNumber)
		if err != nil {
			return nil, errors.New("cms: marshal RID: " + err.Error())
		}
		// RecipientEncryptedKey = SEQUENCE { RID, EncryptedKey }
		encKeyDER, err := asn1.Marshal(wrappedCEK)
		if err != nil {
			return nil, errors.New("cms: marshal encKey: " + err.Error())
		}
		rekDER := marshalSEQ(append(ridDER, encKeyDER...))
		// RecipientEncryptedKeys = SEQUENCE OF { rek }
		reksDER := marshalSEQ(rekDER)

		// Originator [0] EXPLICIT containing raw PK bytes
		originatorDER := marshalEXPLICIT(0, tlv(0xa1, senderPKBytes))

		// UKM [1] EXPLICIT OCTET STRING
		ukmValDER, err := asn1.Marshal(ukm)
		if err != nil {
			return nil, errors.New("cms: marshal UKM: " + err.Error())
		}
		ukmDER := marshalEXPLICIT(1, ukmValDER)

		// KeyEncryptionAlgorithm
		keyEncAlgDER, err := asn1.Marshal(AlgorithmIdentifier{Algorithm: OIDGost28147Wrap})
		if err != nil {
			return nil, errors.New("cms: marshal keyEncAlg: " + err.Error())
		}

		// Version
		versionDER, err := asn1.Marshal(3)
		if err != nil {
			return nil, err
		}

		// KeyAgreeRecipientInfo = SEQUENCE { version, originator, ukm, keyEncAlg, reks }
		kariInner := versionDER
		kariInner = append(kariInner, originatorDER...)
		kariInner = append(kariInner, ukmDER...)
		kariInner = append(kariInner, keyEncAlgDER...)
		kariInner = append(kariInner, reksDER...)
		// Wrap in context [1] for KeyAgreeRecipientInfo (RFC 5652: [1] IMPLICIT SEQUENCE)
		recipiInfosDER = append(recipiInfosDER, tlv(0xa1, kariInner)...)
	}
	recipientsRaw := asn1.RawValue{FullBytes: marshalSETOF(recipiInfosDER)}

	// 7. Build EncryptedContentInfo
	eci := EncryptedContentInfo{
		ContentType: OIDData,
		ContentEncryptionAlgorithm: encContentAlgID{
			Algorithm:  OIDGost28147CFB,
			Parameters: gost28147Params{IV: iv},
		},
		EncryptedContent: ciphertext,
	}

	ed := rawEnvelopedData{
		Version:              2,
		RecipientInfos:       recipientsRaw,
		EncryptedContentInfo: eci,
	}

	edDER, err := asn1.Marshal(ed)
	if err != nil {
		return nil, errors.New("cms: marshal EnvelopedData: " + err.Error())
	}

	// Marshal as SEQUENCE { OID, [0] EXPLICIT edDER } (same pattern as Sign)
	oidDER, err := asn1.Marshal(OIDEnvelopedData)
	if err != nil {
		return nil, err
	}
	inner := append(oidDER, marshalEXPLICIT(0, edDER)...)
	return marshalSEQ(inner), nil
}

// ParseEnveloped parses a DER-encoded ContentInfo/EnvelopedData.
func ParseEnveloped(der []byte) (*EncryptedMessage, error) {
	_, edBytes, err := parseContentInfo(der, OIDEnvelopedData)
	if err != nil {
		return nil, err
	}

	var ed rawEnvelopedData
	if _, err := asn1.Unmarshal(edBytes, &ed); err != nil {
		return nil, errors.New("cms: parse EnvelopedData: " + err.Error())
	}

	msg := &EncryptedMessage{
		Algorithm:  ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm,
		IV:         ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.IV,
		CipherText: ed.EncryptedContentInfo.EncryptedContent,
	}

	// Parse recipients from the SET
	msg.Recipients, _ = parseRecipients(ed.RecipientInfos.Bytes)

	return msg, nil
}

// DecryptEnveloped decrypts an EncryptedMessage using the recipient's private key.
func DecryptEnveloped(msg *EncryptedMessage, key *dstu4145.PrivateKey, myCert *cert.Certificate) ([]byte, error) {
	// Find matching recipient by serial number (and issuer when available).
	var rcpt *parsedRecipient
	for i := range msg.Recipients {
		r := &msg.Recipients[i]
		if r.SerialNumber == nil || myCert.SerialNumber == nil {
			continue
		}
		if r.SerialNumber.Cmp(myCert.SerialNumber) != 0 {
			continue
		}
		// Issuer comparison: try FullBytes first, fall back to Bytes
		rIssuer := r.Issuer.FullBytes
		if len(rIssuer) == 0 {
			rIssuer = r.Issuer.Bytes
		}
		myIssuer := myCert.Issuer.FullBytes
		if len(myIssuer) == 0 {
			myIssuer = myCert.Issuer.Bytes
		}
		if len(rIssuer) > 0 && len(myIssuer) > 0 && !bytesEqual(rIssuer, myIssuer) {
			continue
		}
		rcpt = r
		break
	}
	if rcpt == nil {
		return nil, errors.New("cms: DecryptEnveloped: no matching recipient")
	}

	// Reconstruct originator public key
	originatorPub, err := rebuildPublicKey(key, rcpt.OriginatorPK)
	if err != nil {
		return nil, errors.New("cms: rebuild originator public key: " + err.Error())
	}

	// Derive KEK
	kek, err := dstu15946.KeyAgreement(key, originatorPub, rcpt.UKM, gost34311.New)
	if err != nil {
		return nil, errors.New("cms: KeyAgreement: " + err.Error())
	}
	if len(kek) > 32 {
		kek = kek[:32]
	}

	// Unwrap CEK
	cek, err := gost28147.UnwrapKey(kek, rcpt.WrappedCEK)
	if err != nil {
		return nil, errors.New("cms: UnwrapKey: " + err.Error())
	}

	// Decrypt content
	return gost28147.DecryptCFB(cek, msg.IV, msg.CipherText)
}

// encodePublicKeyUncompressed returns uncompressed BE X||Y for a public key.
func encodePublicKeyUncompressed(pub *dstu4145.PublicKey, byteLen int) []byte {
	xBytes := pub.Q.X.Bytes()
	yBytes := pub.Q.Y.Bytes()
	// BE-pad to byteLen
	x := make([]byte, byteLen)
	y := make([]byte, byteLen)
	copy(x[byteLen-len(xBytes):], xBytes)
	copy(y[byteLen-len(yBytes):], yBytes)
	return append(x, y...)
}

// rebuildPublicKey reconstructs a PublicKey on the same curve as key from raw BE X||Y bytes.
func rebuildPublicKey(key *dstu4145.PrivateKey, pkBytes []byte) (*dstu4145.PublicKey, error) {
	curve := key.Curve
	byteLen := (curve.M + 7) / 8
	if len(pkBytes) < 2*byteLen {
		return nil, errors.New("cms: public key bytes too short")
	}
	return rebuildPubFromBEXY(curve, pkBytes[:byteLen], pkBytes[byteLen:2*byteLen])
}

// rebuildPubFromBEXY creates a dstu4145.PublicKey from big-endian X and Y byte slices on the given curve.
func rebuildPubFromBEXY(curve *ec.Curve, xBE, yBE []byte) (*dstu4145.PublicKey, error) {
	words := curve.Words
	x := gf2m.FromBytes(xBE, words)
	y := gf2m.FromBytes(yBE, words)
	pt := ec.NewPoint(curve, x, y)
	if !curve.Contains(pt) {
		return nil, errors.New("cms: rebuilt public key point not on curve")
	}
	return &dstu4145.PublicKey{Q: pt, Curve: curve}, nil
}

// marshalIssuerAndSerial manually encodes an IssuerAndSerialNumber SEQUENCE.
// This avoids the Go asn1 bug where RawValue+*big.Int produces wrong length.
func marshalIssuerAndSerial(issuer asn1.RawValue, serial *big.Int) ([]byte, error) {
	issuerBytes := issuer.FullBytes
	if len(issuerBytes) == 0 {
		issuerBytes = issuer.Bytes
	}
	serialDER, err := asn1.Marshal(serial)
	if err != nil {
		return nil, err
	}
	inner := append(issuerBytes, serialDER...)
	return marshalSEQ(inner), nil
}

// parseRecipients parses the inner bytes of a SET OF RecipientInfo.
func parseRecipients(data []byte) ([]parsedRecipient, error) {
	var recipients []parsedRecipient
	for len(data) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(data, &raw)
		if err != nil {
			break
		}
		data = rest

		// Each element should be context-tagged KeyAgreeRecipientInfo ([1])
		if raw.Class == 2 && raw.Tag == 1 {
			rcpts, err := parseKeyAgreeRecipientInfo(raw.Bytes)
			if err != nil {
				continue
			}
			recipients = append(recipients, rcpts...)
		}
	}
	return recipients, nil
}

// parseKeyAgreeRecipientInfo manually parses a KeyAgreeRecipientInfo from its inner bytes.
func parseKeyAgreeRecipientInfo(data []byte) ([]parsedRecipient, error) {
	// Version
	var version int
	rest, err := asn1.Unmarshal(data, &version)
	if err != nil {
		return nil, errors.New("cms: KARI version: " + err.Error())
	}

	// Originator [0] EXPLICIT
	var originatorRaw asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &originatorRaw)
	if err != nil {
		return nil, errors.New("cms: KARI originator: " + err.Error())
	}
	// originatorRaw is [0] EXPLICIT containing [1] { rawPKbytes }
	// Unwrap inner context tag to get the actual PK bytes
	originatorPK := originatorRaw.Bytes
	if len(originatorPK) > 2 && (originatorPK[0]&0xc0) == 0x80 {
		// strip context tag: class=2 (context) bits are 10xxxxxx
		var innerRaw asn1.RawValue
		if _, err2 := asn1.Unmarshal(originatorPK, &innerRaw); err2 == nil {
			originatorPK = innerRaw.Bytes
		}
	}

	// Optional UKM [1] EXPLICIT
	var ukm []byte
	if len(rest) > 0 && rest[0] == 0xa1 {
		var ukmRaw asn1.RawValue
		r, err := asn1.Unmarshal(rest, &ukmRaw)
		if err != nil {
			return nil, errors.New("cms: KARI UKM: " + err.Error())
		}
		// UKM is EXPLICIT [1] { OCTET STRING }
		var ukmBytes []byte
		if _, err := asn1.Unmarshal(ukmRaw.Bytes, &ukmBytes); err == nil {
			ukm = ukmBytes
		} else {
			ukm = ukmRaw.Bytes
		}
		rest = r
	}

	// KeyEncryptionAlgorithm AlgorithmIdentifier
	var keyEncAlg AlgorithmIdentifier
	rest, err = asn1.Unmarshal(rest, &keyEncAlg)
	if err != nil {
		return nil, errors.New("cms: KARI keyEncAlg: " + err.Error())
	}

	// RecipientEncryptedKeys SEQUENCE OF RecipientEncryptedKey
	var rekSeq asn1.RawValue
	_, err = asn1.Unmarshal(rest, &rekSeq)
	if err != nil {
		return nil, errors.New("cms: KARI rekSeq: " + err.Error())
	}

	var recipients []parsedRecipient
	tmp := rekSeq.Bytes
	for len(tmp) > 0 {
		var rekSeqItem asn1.RawValue
		tmp2, err := asn1.Unmarshal(tmp, &rekSeqItem)
		if err != nil {
			break
		}
		tmp = tmp2

		// Parse RID (IssuerAndSerialNumber) manually
		var issuer asn1.RawValue
		var serial *big.Int
		rekInner := rekSeqItem.Bytes
		// RID is a SEQUENCE { Issuer, SerialNumber }
		var ridSeq asn1.RawValue
		rekRest, err := asn1.Unmarshal(rekInner, &ridSeq)
		if err != nil {
			continue
		}
		// Parse issuer RawValue from ridSeq.Bytes
		var issuerRaw asn1.RawValue
		ridRest, err := asn1.Unmarshal(ridSeq.Bytes, &issuerRaw)
		if err != nil {
			continue
		}
		issuer = asn1.RawValue{FullBytes: ridSeq.Bytes[:len(ridSeq.Bytes)-len(ridRest)]}
		if _, err := asn1.Unmarshal(ridRest, &serial); err != nil {
			continue
		}

		// EncryptedKey OCTET STRING
		var encKey []byte
		if _, err := asn1.Unmarshal(rekRest, &encKey); err != nil {
			continue
		}

		recipients = append(recipients, parsedRecipient{
			Issuer:       issuer,
			SerialNumber: serial,
			OriginatorPK: originatorPK,
			UKM:          ukm,
			WrappedCEK:   encKey,
		})
	}
	return recipients, nil
}
