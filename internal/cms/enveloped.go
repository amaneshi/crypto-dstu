package cms

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"
	"slices"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
	"github.com/amaneshi/crypto-dstu/pkg/ec"
	"github.com/amaneshi/crypto-dstu/pkg/gf2m"
	"github.com/amaneshi/crypto-dstu/pkg/gost28147"
	"github.com/amaneshi/crypto-dstu/pkg/kalyna"
)

// OIDs for EnvelopedData algorithms.
var (
	OIDGost28147CFB  = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 3}
	OIDGost28147Wrap = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 1, 5}
	OIDDSTU4145DH    = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 4}
	OIDKalyna256CFB  = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 3, 3, 2}
	OIDKalyna256OFB  = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 3, 6, 2}
	OIDKalynaWrap    = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 1, 3, 11}
	OIDKupynaDH      = asn1.ObjectIdentifier{1, 2, 804, 2, 1, 1, 1, 1, 3, 7}
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
	IV  []byte
	DKE []byte `asn1:"optional"`
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
	Algorithm              asn1.ObjectIdentifier
	IV                     []byte
	CipherText             []byte
	Recipients             []parsedRecipient
	OriginatorCertificates []*cert.Certificate
}

type parsedRecipient struct {
	AgreementAlgorithm asn1.ObjectIdentifier
	Issuer             asn1.RawValue
	SerialNumber       *big.Int
	OriginatorPK       []byte // compressed/raw public key bytes from originator
	OriginatorID       *originatorIdentifier
	UKM                []byte
	WrappedCEK         []byte
}

// Encrypt encrypts content for one or more recipients using ECDH + GOST28147 CFB.
// senderKey is the sender's ephemeral or static private key.
// Returns DER-encoded ContentInfo wrapping EnvelopedData.
func Encrypt( //nolint:funlen
	content []byte,
	recipients []*cert.Certificate,
	senderKey *dstu4145.PrivateKey,
) ([]byte, error) {
	return encrypt(content, recipients, senderKey, nil, nil, false)
}

// EncryptWithOriginatorCertificate identifies the static agreement key by the
// sender certificate's issuer and serial. Recipients must have that certificate.
func EncryptWithOriginatorCertificate(content []byte, recipients []*cert.Certificate, senderKey *dstu4145.PrivateKey, senderCert *cert.Certificate) ([]byte, error) {
	if senderKey == nil || senderKey.D == nil {
		return nil, errors.New("cms: sender key is required")
	}
	if senderCert == nil || senderCert.SerialNumber == nil || senderCert.SerialNumber.Sign() <= 0 {
		return nil, errors.New("cms: sender certificate is required")
	}
	if err := cert.VerifyCertPKMatch(senderCert, senderKey); err != nil {
		return nil, err
	}
	if err := cert.CheckEncryptionUsage(senderCert); err != nil {
		return nil, err
	}
	return encrypt(content, recipients, senderKey, senderCert, nil, false)
}

func encrypt(
	content []byte,
	recipients []*cert.Certificate,
	senderKey *dstu4145.PrivateKey,
	senderCert *cert.Certificate,
	algorithm asn1.ObjectIdentifier,
	embedSender bool,
) ([]byte, error) {
	if len(algorithm) == 0 {
		algorithm = OIDGost28147CFB
	}
	profile, err := profileForCipher(algorithm)
	if err != nil {
		return nil, err
	}
	if senderKey == nil || senderKey.Curve == nil || senderKey.D == nil || senderKey.D.Sign() <= 0 || senderKey.D.Cmp(new(big.Int).SetBytes(senderKey.Curve.N)) >= 0 {
		return nil, errors.New("cms: sender key is required")
	}
	if len(recipients) == 0 {
		return nil, errors.New("cms: Encrypt: no recipients")
	}

	// 1. Generate a random CEK and profile-sized IV.
	cek := make([]byte, 32)
	defer clear(cek)
	if _, err := rand.Read(cek); err != nil {
		return nil, errors.New("cms: generate CEK: " + err.Error())
	}
	iv := make([]byte, profile.ivSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, errors.New("cms: generate IV: " + err.Error())
	}

	// 2. Encrypt content with the selected profile.
	ciphertext, err := cryptEnvelopeContent(profile, cek, iv, content, false)
	if err != nil {
		return nil, errors.New("cms: encrypt content: " + err.Error())
	}

	// 3. Embed the national compressed public key as OCTET STRING inside BIT STRING.
	senderPub := senderKey.Public()
	senderPKBytes, err := asn1.Marshal(reverseBytes(senderPub.Q.Compress()))
	if err != nil {
		return nil, err
	}

	// 4. Generate random UKM (64 bytes)
	ukm := make([]byte, 64)
	if _, err = rand.Read(ukm); err != nil {
		return nil, errors.New("cms: generate UKM: " + err.Error())
	}

	// 5. For each recipient: ECDH → DeriveKey → WrapKey
	var recipiInfosDER []byte
	var wrappedCEK []byte
	var ridDER []byte
	var encKeyDER []byte
	var ukmValDER []byte
	var keyEncAlgDER []byte
	var versionDER []byte
	for _, rcpt := range recipients {
		if rcpt == nil || rcpt.PublicKey == nil {
			return nil, errors.New("cms: recipient has no public key")
		}

		if err := cert.CheckEncryptionUsage(rcpt); err != nil {
			return nil, err
		}
		var kek []byte
		kek, err = envelopeKEK(senderKey, rcpt.PublicKey, ukm, profile.agreement)
		if err != nil {
			return nil, errors.New("cms: KeyAgreement: " + err.Error())
		}
		if len(kek) > 32 {
			kek = kek[:32]
		}

		// Generate an independent wrap IV for this recipient.
		wrapIV := make([]byte, profile.ivSize)
		if _, err = rand.Read(wrapIV); err != nil {
			return nil, errors.New("cms: generate wrapIV: " + err.Error())
		}

		if profile.wrap.Equal(OIDKalynaWrap) {
			wrappedCEK, err = kalyna.WrapKey(kek, cek, wrapIV)
		} else {
			wrappedCEK, err = gost28147.WrapKey(kek, cek, wrapIV)
		}
		clear(kek)
		if err != nil {
			return nil, errors.New("cms: WrapKey: " + err.Error())
		}

		// Build RID (IssuerAndSerialNumber) manually to avoid asn1.RawValue length bug
		ridDER, err = marshalIssuerAndSerial(rcpt.Issuer, rcpt.SerialNumber)
		if err != nil {
			return nil, errors.New("cms: marshal RID: " + err.Error())
		}
		// RecipientEncryptedKey = SEQUENCE { RID, EncryptedKey }
		encKeyDER, err = asn1.Marshal(wrappedCEK)
		if err != nil {
			return nil, errors.New("cms: marshal encKey: " + err.Error())
		}
		rekDER := marshalSEQ(append(ridDER, encKeyDER...))
		// RecipientEncryptedKeys = SEQUENCE OF { rek }
		reksDER := marshalSEQ(rekDER)

		// The originator key inherits the recipient's curve parameters.
		originatorKey := struct {
			Algorithm AlgorithmIdentifier
			PublicKey asn1.BitString
		}{
			Algorithm: AlgorithmIdentifier{Algorithm: dstu4145.OIDDstu4145WithGost34311, Parameters: asn1.RawValue{Tag: asn1.TagNull}},
			PublicKey: asn1.BitString{Bytes: senderPKBytes, BitLength: len(senderPKBytes) * 8},
		}
		if profile.agreement.Equal(OIDKupynaDH) {
			originatorKey.Algorithm.Algorithm = dstu4145.OIDDstu4145WithKupyna256
		}
		originatorKeyDER, err := asn1.Marshal(originatorKey)
		if err != nil {
			return nil, err
		}
		originatorKeyDER[0] = 0xa1
		originatorDER := marshalEXPLICIT(0, originatorKeyDER)
		if senderCert != nil {
			identifier, err := marshalIssuerAndSerial(senderCert.Issuer, senderCert.SerialNumber)
			if err != nil {
				return nil, err
			}
			originatorDER = marshalEXPLICIT(0, identifier)
		}

		// UKM [1] EXPLICIT OCTET STRING
		ukmValDER, err = asn1.Marshal(ukm)
		if err != nil {
			return nil, errors.New("cms: marshal UKM: " + err.Error())
		}
		ukmDER := marshalEXPLICIT(1, ukmValDER)

		// KeyEncryptionAlgorithm
		wrapAlgorithm, err := asn1.Marshal(AlgorithmIdentifier{Algorithm: profile.wrap, Parameters: asn1.RawValue{Tag: asn1.TagNull}})
		if err != nil {
			return nil, err
		}
		keyEncAlgDER, err = asn1.Marshal(AlgorithmIdentifier{Algorithm: profile.agreement, Parameters: asn1.RawValue{FullBytes: wrapAlgorithm}})
		if err != nil {
			return nil, errors.New("cms: marshal keyEncAlg: " + err.Error())
		}

		// Version
		versionDER, err = asn1.Marshal(3)
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
			Algorithm:  profile.content,
			Parameters: gost28147Params{IV: iv, DKE: profile.dke},
		},
		EncryptedContent: ciphertext,
	}

	ed := rawEnvelopedData{
		Version:              2,
		RecipientInfos:       recipientsRaw,
		EncryptedContentInfo: eci,
	}

	if embedSender {
		ed.OriginatorInfo = asn1.RawValue{FullBytes: tlv(0xa0, tlv(0xa0, senderCert.Raw))}
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
	return marshalSEQ(slices.Concat(oidDER, marshalEXPLICIT(0, edDER))), nil
}

// ParseEnveloped parses a DER-encoded ContentInfo/EnvelopedData.
func ParseEnveloped(der []byte) (*EncryptedMessage, error) {
	edBytes, err := parseContentInfo(der, OIDEnvelopedData)
	if err != nil {
		return nil, err
	}

	var ed rawEnvelopedData
	rest, err := asn1.Unmarshal(edBytes, &ed)
	if err != nil {
		return nil, errors.New("cms: parse EnvelopedData: " + err.Error())
	}
	if len(rest) != 0 || !ed.EncryptedContentInfo.ContentType.Equal(OIDData) {
		return nil, errors.New("cms: malformed encrypted content")
	}
	dke := ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.DKE
	if len(dke) != 0 && !bytesEqual(dke, gost28147.SboxDSTU.Packed()) {
		return nil, errors.New("cms: unsupported content encryption DKE")
	}
	profile, err := profileForCipher(ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if len(ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.IV) != profile.ivSize || profile.ivSize == 32 && len(dke) != 0 {
		return nil, errors.New("cms: invalid content encryption parameters")
	}
	if profile.ivSize == 32 {
		canonical, marshalErr := asn1.Marshal(ed)
		if marshalErr != nil || !bytesEqual(canonical, edBytes) {
			return nil, errors.New("cms: noncanonical Kalyna envelope parameters")
		}
	}

	msg := &EncryptedMessage{
		Algorithm:  ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm,
		IV:         ed.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.IV,
		CipherText: ed.EncryptedContentInfo.EncryptedContent,
	}

	// Parse recipients from the SET
	msg.Recipients, err = parseRecipients(ed.RecipientInfos.Bytes)
	if err != nil {
		return nil, err
	}
	if len(msg.Recipients) == 0 {
		return nil, errors.New("cms: no supported key-agreement recipients")
	}
	for _, recipient := range msg.Recipients {
		if !recipient.AgreementAlgorithm.Equal(profile.agreement) {
			return nil, errors.New("cms: mismatched content and agreement profiles")
		}
	}
	if len(ed.OriginatorInfo.FullBytes) != 0 {
		if ed.OriginatorInfo.Class != 2 || ed.OriginatorInfo.Tag != 0 || !ed.OriginatorInfo.IsCompound {
			return nil, errors.New("cms: malformed originator info wrapper")
		}
		var info struct {
			Certificates asn1.RawValue `asn1:"optional,tag:0"`
			CRLs         asn1.RawValue `asn1:"optional,tag:1"`
		}
		if rest, parseErr := asn1.Unmarshal(tlv(0x30, ed.OriginatorInfo.Bytes), &info); parseErr != nil || len(rest) != 0 {
			return nil, errors.New("cms: malformed originator info")
		}
		if len(info.Certificates.Bytes) != 0 {
			msg.OriginatorCertificates, err = cert.ParseCertificates(info.Certificates.Bytes)
			if err != nil {
				return nil, err
			}
		}
	}

	return msg, nil
}

// DecryptEnveloped decrypts an EncryptedMessage using the recipient's private key.
// Additional certificates supply agreement keys for static originators. Neither
// these nor embedded originator certificates become trust anchors.
func DecryptEnveloped(msg *EncryptedMessage, key *dstu4145.PrivateKey, myCert *cert.Certificate, originators ...*cert.Certificate) ([]byte, error) {
	if msg == nil || key == nil || myCert == nil {
		return nil, errors.New("cms: missing decryption parameters")
	}
	if !msg.Algorithm.Equal(OIDGost28147CFB) && !msg.Algorithm.Equal(OIDKalyna256CFB) && !msg.Algorithm.Equal(OIDKalyna256OFB) {
		return nil, errors.New("cms: unsupported content encryption algorithm")
	}
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
	var originatorPub *dstu4145.PublicKey
	var err error
	if rcpt.OriginatorID != nil {
		candidates := append([]*cert.Certificate{myCert}, msg.OriginatorCertificates...)
		candidates = append(candidates, originators...)
		originatorPub, err = resolveOriginator(rcpt.OriginatorID, candidates)
	} else {
		originatorPub, err = rebuildPublicKey(key, rcpt.OriginatorPK)
	}
	if err != nil {
		return nil, errors.New("cms: rebuild originator public key: " + err.Error())
	}

	// Derive the KEK for the explicitly parsed agreement profile.
	profile, err := profileForCipher(msg.Algorithm)
	if err != nil {
		return nil, err
	}
	if !rcpt.AgreementAlgorithm.Equal(profile.agreement) || len(msg.IV) != profile.ivSize {
		return nil, errors.New("cms: mismatched encryption profile")
	}
	kek, err := envelopeKEK(key, originatorPub, rcpt.UKM, rcpt.AgreementAlgorithm)
	if err != nil {
		return nil, err
	}
	defer clear(kek)

	// Unwrap CEK
	var cek []byte
	if rcpt.AgreementAlgorithm.Equal(OIDKupynaDH) {
		cek, err = kalyna.UnwrapKey(kek, rcpt.WrappedCEK)
	} else {
		cek, err = gost28147.UnwrapKey(kek, rcpt.WrappedCEK)
	}
	if err != nil {
		return nil, errors.New("cms: UnwrapKey: " + err.Error())
	}

	defer clear(cek)
	return cryptEnvelopeContent(profile, cek, msg.IV, msg.CipherText, true)
}

// encodePublicKeyUncompressed returns uncompressed BE X||Y for a public key.
func encodePublicKeyUncompressed(pub *dstu4145.PublicKey, byteLen int) []byte {
	xBytes := pub.Q.X.Bytes()
	yBytes := pub.Q.Y.Bytes()
	// BE-pad to byteLen
	out := make([]byte, 2*byteLen)
	copy(out[byteLen-len(xBytes):], xBytes)
	copy(out[2*byteLen-len(yBytes):], yBytes)
	return out
}

// rebuildPublicKey reconstructs a PublicKey on the same curve as key from raw BE X||Y bytes.
func rebuildPublicKey(key *dstu4145.PrivateKey, pkBytes []byte) (*dstu4145.PublicKey, error) {
	curve := key.Curve
	byteLen := (curve.M + 7) / 8
	var compressed []byte
	if rest, err := asn1.Unmarshal(pkBytes, &compressed); err == nil && len(rest) == 0 && len(compressed) == byteLen {
		point, err := curve.Expand(reverseBytes(compressed))
		if err != nil {
			return nil, err
		}
		return &dstu4145.PublicKey{Q: point, Curve: curve}, nil
	}
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
	return marshalSEQ(slices.Concat(issuerBytes, serialDER)), nil
}

// parseRecipients parses the inner bytes of a SET OF RecipientInfo.
func parseRecipients(data []byte) ([]parsedRecipient, error) {
	var recipients []parsedRecipient
	for len(data) > 0 {
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(data, &raw)
		if err != nil {
			return nil, err
		}
		data = rest

		// Each element should be context-tagged KeyAgreeRecipientInfo ([1])
		if raw.Class == 2 && raw.Tag == 1 && raw.IsCompound {
			rcpts, rcptErr := parseKeyAgreeRecipientInfo(raw.Bytes)
			if rcptErr != nil {
				return nil, rcptErr
			}
			recipients = append(recipients, rcpts...)
		} else {
			return nil, errors.New("cms: unsupported recipient info")
		}
	}
	return recipients, nil
}

// parseKeyAgreeRecipientInfo manually parses a KeyAgreeRecipientInfo from its inner bytes.
func parseKeyAgreeRecipientInfo(data []byte) ([]parsedRecipient, error) { //nolint:funlen
	// Version
	var version int
	rest, err := asn1.Unmarshal(data, &version)
	if err != nil {
		return nil, errors.New("cms: KARI version: " + err.Error())
	}
	if version != 3 {
		return nil, errors.New("cms: unsupported KARI version")
	}

	// Originator [0] EXPLICIT
	var originatorRaw asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &originatorRaw)
	if err != nil {
		return nil, errors.New("cms: KARI originator: " + err.Error())
	}
	originatorPK, originatorID, err := parseOriginator(originatorRaw)
	if err != nil {
		return nil, err
	}

	// Optional UKM [1] EXPLICIT
	var ukm []byte
	var ukmRaw asn1.RawValue
	if len(rest) > 0 && rest[0] == 0xa1 {
		rest, err = asn1.Unmarshal(rest, &ukmRaw)
		if err != nil {
			return nil, errors.New("cms: KARI UKM: " + err.Error())
		}
		// UKM is EXPLICIT [1] { OCTET STRING }
		if remaining, parseErr := asn1.Unmarshal(ukmRaw.Bytes, &ukm); parseErr != nil || len(remaining) != 0 || len(ukm) != 64 {
			return nil, errors.New("cms: malformed key agreement UKM")
		}
	}

	// KeyEncryptionAlgorithm AlgorithmIdentifier
	var keyEncAlg AlgorithmIdentifier
	rest, err = asn1.Unmarshal(rest, &keyEncAlg)
	if err != nil {
		return nil, errors.New("cms: KARI keyEncAlg: " + err.Error())
	}
	var wrapAlgorithm AlgorithmIdentifier
	if remaining, parseErr := asn1.Unmarshal(keyEncAlg.Parameters.FullBytes, &wrapAlgorithm); parseErr != nil || len(remaining) != 0 {
		return nil, errors.New("cms: unsupported key agreement or wrapping algorithm")
	}
	wrappedLength := 44
	if keyEncAlg.Algorithm.Equal(OIDKupynaDH) && wrapAlgorithm.Algorithm.Equal(OIDKalynaWrap) {
		if !bytesEqual(wrapAlgorithm.Parameters.FullBytes, []byte{5, 0}) {
			return nil, errors.New("cms: Kalyna wrap parameters must be NULL")
		}
		canonical, marshalErr := asn1.Marshal(wrapAlgorithm)
		if marshalErr != nil || !bytesEqual(canonical, keyEncAlg.Parameters.FullBytes) {
			return nil, errors.New("cms: invalid Kalyna wrap parameters")
		}
		wrappedLength = 96
	} else if !keyEncAlg.Algorithm.Equal(OIDDSTU4145DH) || !wrapAlgorithm.Algorithm.Equal(OIDGost28147Wrap) {
		return nil, errors.New("cms: unsupported key agreement or wrapping algorithm")
	}

	// RecipientEncryptedKeys uses IssuerAndSerialNumber in the supported profile.
	var keys []struct {
		RID struct {
			Issuer asn1.RawValue
			Serial *big.Int
		}
		Wrapped []byte
	}
	if trailing, parseErr := asn1.Unmarshal(rest, &keys); parseErr != nil || len(trailing) != 0 || len(keys) == 0 {
		return nil, errors.New("cms: malformed recipient encrypted keys")
	}
	recipients := make([]parsedRecipient, 0, len(keys))
	for _, key := range keys {
		if key.RID.Serial == nil || key.RID.Serial.Sign() <= 0 || key.RID.Issuer.Class != 0 || key.RID.Issuer.Tag != asn1.TagSequence || len(key.Wrapped) != wrappedLength {
			return nil, errors.New("cms: malformed recipient identifier or wrapped key")
		}
		recipients = append(recipients, parsedRecipient{
			AgreementAlgorithm: keyEncAlg.Algorithm,
			Issuer:             key.RID.Issuer, SerialNumber: key.RID.Serial,
			OriginatorPK: originatorPK, OriginatorID: originatorID,
			UKM: ukm, WrappedCEK: key.Wrapped,
		})
	}
	return recipients, nil
}
