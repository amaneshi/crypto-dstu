package ua

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/transport"
)

// SignOptions controls SignDocument behaviour.
type SignOptions struct {
	Encryption      EncryptionOptions     // used by SignAndEncrypt
	Timestamp       *TimestampSignOptions // nil leaves the signature untimestamped
	DigestAlgorithm asn1.ObjectIdentifier // optional explicit supported digest profile
	Detached        bool                  // omit content from CMS (detached signature)
	NoTax           bool                  // return raw CMS DER; skip transport container wrapping
	Filename        string                // FILENAME field in transport header
	Email           string                // SND_EMAIL field in transport header
}

// SignerResult holds per-signer verification output.
type SignerResult struct {
	CertInfo         *CertInfo
	SigningTime      time.Time // claimed CMS signingTime, not an authenticated timestamp
	Valid            bool
	Error            error
	RevocationStatus RevocationStatus
}

// TimestampResult holds per-timestamp verification output.
type TimestampResult struct {
	SignerIndex      int
	TSA              *CertInfo
	RevocationStatus RevocationStatus
	Time             time.Time
	Type             string // "signature" or "content"
	Valid            bool
	Error            error
}

// TransportHeader carries metadata extracted from an Ukrainian tax office transport container.
type TransportHeader struct {
	Filename  string
	SndEmail  string
	RcvEmail  string
	CerType   string
	CRC32Sign string
	CRC32File string
}

// UnsignResult is the output of UnsignDocument.
type UnsignResult struct {
	Content    []byte
	Signers    []SignerResult
	Timestamps []TimestampResult
	Header     *TransportHeader
}

// SignDocument signs content and returns either raw CMS DER (NoTax=true)
// or a transport container (NoTax=false).
func (b *Box) SignDocument(content []byte, opts SignOptions) ([]byte, error) {
	return b.SignDocumentWithContext(context.Background(), content, opts)
}

// SignDocumentWithContext signs and optionally obtains an authenticated timestamp
// before returning CMS or transport bytes. No partial document is returned.
func (b *Box) SignDocumentWithContext(ctx context.Context, content []byte, opts SignOptions) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("ua: signing context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	content = bytes.Clone(content)
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	if entry.signCert == nil {
		return nil, errors.New("ua: SignDocument: no signing certificate loaded")
	}

	cmsOpts := cms.SignOptions{Detached: opts.Detached, DigestAlgorithm: opts.DigestAlgorithm}
	cmsDER, err := cms.Sign(content, entry.privateKey, entry.signCert, cmsOpts)
	if err != nil {
		return nil, errors.New("ua: SignDocument: " + err.Error())
	}

	if opts.Timestamp != nil {
		cmsDER, err = b.addSignatureTimestamp(ctx, cmsDER, *opts.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("ua: signature timestamp: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.NoTax {
		return cmsDER, nil
	}

	// Wrap in transport container
	filename := opts.Filename
	if filename == "" {
		filename = defaultFilename
	}

	header := &transport.Header{
		Filename:  filename,
		SndEmail:  opts.Email,
		CerType:   "UA1",
		CRC32Sign: transport.CRC32Hex(cmsDER),
	}
	if !opts.Detached {
		header.CRC32File = transport.CRC32Hex(content)
	}

	container := &transport.Container{
		Header: header,
		Sections: []transport.Section{
			{Label: "UA1_SIGN", Contents: cmsDER},
		},
	}
	return transport.Encode(container), nil
}

// UnsignDocument parses and verifies a signed document.
// Accepts transport container bytes or raw CMS DER.
func (b *Box) UnsignDocument(data []byte) (*UnsignResult, error) {
	return b.UnsignDocumentWithContent(data, nil)
}

// UnsignDocumentWithContent verifies a detached signature using originalContent.
// A configured CA bundle (or explicit certificate pin) is required for trust.
func (b *Box) UnsignDocumentWithContent(data, originalContent []byte) (*UnsignResult, error) {
	return b.UnsignDocumentWithOptions(context.Background(), data, originalContent, VerificationOptions{})
}

// UnsignDocumentWithOptions verifies every signature and the requested revocation
// policy before releasing any content. originalContent supplies detached bytes.
func (b *Box) UnsignDocumentWithOptions(ctx context.Context, data, originalContent []byte, options VerificationOptions) (*UnsignResult, error) {
	result := &UnsignResult{}
	if ctx == nil {
		return nil, errors.New("ua: verification context is required")
	}
	options, err := options.normalized()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Fetch callbacks must not be able to change the bytes already authenticated.
	data = bytes.Clone(data)
	originalContent = bytes.Clone(originalContent)

	cmsDER := data
	// Try transport container first
	if container, err := transport.Decode(data); err == nil {
		if h := container.Header; h != nil {
			result.Header = &TransportHeader{
				Filename:  h.Filename,
				SndEmail:  h.SndEmail,
				RcvEmail:  h.RcvEmail,
				CerType:   h.CerType,
				CRC32Sign: h.CRC32Sign,
				CRC32File: h.CRC32File,
			}
		}
		// Find a sign section
		for _, label := range []string{"UA_SIGN1", "UA1_SIGN"} {
			if s := container.FindSection(label); s != nil {
				cmsDER = s.Contents
				break
			}
		}
	}

	msg, err := cms.ParseSigned(cmsDER)
	if err != nil {
		return nil, errors.New("ua: UnsignDocument: parse: " + err.Error())
	}

	msg.Certificates = append(msg.Certificates, b.certificates...)
	msg.Certificates = append(msg.Certificates, b.caCerts...)
	for _, e := range b.keys {
		if e.signCert != nil {
			msg.Certificates = append(msg.Certificates, e.signCert)
		}
	}
	cms.ResolveCertificates(msg)
	if len(b.caCerts) == 0 {
		return result, errors.New("ua: trusted CA bundle is required")
	}
	verifyErr := cms.VerifySigned(msg, originalContent, b.caCerts)
	statuses := make([]RevocationStatus, len(msg.Signers))
	for i := range statuses {
		statuses[i] = RevocationNotChecked
	}
	if verifyErr == nil {
		for i := range msg.Signers {
			signer := &msg.Signers[i]
			statuses[i], err = b.checkRevocation(ctx, signer.Certificate, msg.Certificates, options)
			if err != nil {
				signer.Valid, signer.Error = false, err
				verifyErr = errors.Join(verifyErr, err)
			}
		}
	} else if options.Revocation == RevocationRequireOCSP {
		for i := range msg.Signers {
			if msg.Signers[i].Valid {
				msg.Signers[i].Valid = false
				msg.Signers[i].Error = errors.New("ua: required revocation check was not performed after a signature failure")
			}
		}
	}
	if verifyErr == nil && options.TimestampPolicy != TimestampIgnore {
		result.Timestamps, err = b.checkSignatureTimestamps(ctx, msg, options)
		if err != nil {
			verifyErr = errors.Join(verifyErr, err)
		}
	}
	if err := ctx.Err(); err != nil {
		verifyErr = errors.Join(verifyErr, err)
		for i := range msg.Signers {
			msg.Signers[i].Valid = false
			msg.Signers[i].Error = errors.Join(msg.Signers[i].Error, err)
			statuses[i] = RevocationUnavailable
		}
	}
	if verifyErr == nil {
		if originalContent != nil {
			result.Content = originalContent
		} else {
			result.Content = msg.Content
		}
	}

	for i, sr := range msg.Signers {
		r := SignerResult{
			SigningTime:      sr.SigningTime,
			Valid:            sr.Valid,
			Error:            sr.Error,
			RevocationStatus: statuses[i],
		}
		if sr.Certificate != nil {
			r.CertInfo = certInfoFromCert(sr.Certificate)
		}
		result.Signers = append(result.Signers, r)
	}

	if verifyErr != nil {
		return result, fmt.Errorf("ua: signature verification: %w", verifyErr)
	}
	return result, nil
}
