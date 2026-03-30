package ua

import (
	"errors"
	"time"

	"crypto-dstu/cert"
	"crypto-dstu/cms"
	"crypto-dstu/transport"
)

// SignOptions controls SignDocument behaviour.
type SignOptions struct {
	Detached bool   // omit content from CMS (detached signature)
	NoTax    bool   // return raw CMS DER; skip transport container wrapping
	Filename string // FILENAME field in transport header
	Email    string // SND_EMAIL field in transport header
}

// SignerResult holds per-signer verification output.
type SignerResult struct {
	Certificate *cert.Certificate
	CertInfo    *CertInfo
	SigningTime time.Time
	Valid       bool
	Error       error
}

// TimestampResult holds per-timestamp verification output.
type TimestampResult struct {
	Time  time.Time
	Type  string // "signature" or "content"
	Valid bool
	Error error
}

// UnsignResult is the output of UnsignDocument.
type UnsignResult struct {
	Content    []byte
	Signers    []SignerResult
	Timestamps []TimestampResult
	Header     *transport.Header
}

// SignDocument signs content and returns either raw CMS DER (NoTax=true)
// or a transport container (NoTax=false).
func (b *Box) SignDocument(content []byte, opts SignOptions) ([]byte, error) {
	entry, err := b.firstKey()
	if err != nil {
		return nil, err
	}
	if entry.SignCert == nil {
		return nil, errors.New("ua: SignDocument: no signing certificate loaded")
	}

	cmsOpts := cms.SignOptions{Detached: opts.Detached}
	cmsDER, err := cms.Sign(content, entry.PrivateKey, entry.SignCert, cmsOpts)
	if err != nil {
		return nil, errors.New("ua: SignDocument: " + err.Error())
	}

	if opts.NoTax {
		return cmsDER, nil
	}

	// Wrap in transport container
	filename := opts.Filename
	if filename == "" {
		filename = "document.xml"
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
	result := &UnsignResult{}

	cmsDER := data
	// Try transport container first
	if container, err := transport.Decode(data); err == nil {
		result.Header = container.Header
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

	// If no certs were embedded in the CMS, inject known certs from our Box
	// so that SID matching (issuer+serial) can resolve the signer certificates.
	if len(msg.Certificates) == 0 {
		for _, e := range b.Keys {
			if e.SignCert != nil {
				msg.Certificates = append(msg.Certificates, e.SignCert)
			}
		}
		msg.Certificates = append(msg.Certificates, b.CACerts...)
		cms.ResolveCertificates(msg)
	}

	// Verify signatures (pass CACerts for chain check, nil = skip)
	var roots []*cert.Certificate
	if len(b.CACerts) > 0 {
		roots = b.CACerts
	}
	_ = cms.VerifySigned(msg, nil, roots) // best-effort; errors captured per signer

	result.Content = msg.Content

	for _, sr := range msg.Signers {
		r := SignerResult{
			Certificate: sr.Certificate,
			SigningTime: sr.SigningTime,
			Valid:       sr.Valid,
		}
		if sr.Certificate != nil {
			r.CertInfo = certInfoFromCert(sr.Certificate)
		}
		result.Signers = append(result.Signers, r)
	}

	return result, nil
}
