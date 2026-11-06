package ua

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/amaneshi/crypto-dstu/internal/cert"
)

// SignerOptions configures a Signer once, for every key it signs with.
type SignerOptions struct {
	// Timestamp enables a signature timestamp on every document; nil signs
	// without one. Everything about timestamps lives here:
	//   - URLs: TSA endpoints tried in order; empty uses DefaultTSPURL.
	//   - AttemptTimeout: per-endpoint limit, so a hung TSA leaves time for the next.
	//   - TSARoots: trusted TSA anchors. Empty still verifies the token (imprint,
	//     nonce, TSA signature, timestamping EKU, genTime) but not the TSA's
	//     path to a trusted root; trust in the TSA is then left to whoever
	//     verifies the document. Revocation checking requires TSARoots.
	Timestamp *TimestampSignOptions
}

// Signer holds signing configuration (timestamping, TSA endpoints and trust)
// independent of any key. Create it once with NewSigner and call Sign with any
// opened Key. A Signer is immutable and safe for concurrent use.
type Signer struct {
	timestamp *TimestampSignOptions
}

// NewSigner validates opts and returns a Signer. Invalid TSA roots, URLs or
// revocation settings fail here, not on the first Sign.
func NewSigner(opts SignerOptions) (*Signer, error) {
	if opts.Timestamp == nil {
		return &Signer{}, nil
	}
	ts := *opts.Timestamp
	ts.TSARoots = make([][]byte, 0, len(opts.Timestamp.TSARoots))
	for _, der := range opts.Timestamp.TSARoots {
		if _, err := cert.ParseCertificate(bytes.Clone(der)); err != nil {
			return nil, errors.New("ua: NewSigner: invalid TSA root: " + err.Error())
		}
		ts.TSARoots = append(ts.TSARoots, bytes.Clone(der))
	}
	ts.unanchored = len(ts.TSARoots) == 0
	ts.URLs = slices.Clone(opts.Timestamp.URLs)
	if len(ts.URLs) == 0 && ts.Fetch == nil {
		ts.URLs = []string{DefaultTSPURL}
	}
	if err := ts.validate(); err != nil {
		return nil, fmt.Errorf("ua: NewSigner: %w", err)
	}
	if _, err := ts.RevocationOptions.normalized(); err != nil {
		return nil, fmt.Errorf("ua: NewSigner: %w", err)
	}
	return &Signer{timestamp: &ts}, nil
}

// Sign signs content with key and returns raw CMS (opts.NoTax) or a transport
// container, timestamped as configured in NewSigner. opts.Timestamp must be
// nil: timestamping belongs to the Signer. No partial document is returned.
func (s *Signer) Sign(ctx context.Context, key *Key, content []byte, opts SignOptions) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("ua: signing context is required")
	}
	if key == nil || key.entry == nil {
		return nil, errors.New("ua: Sign: key is required")
	}
	if opts.Timestamp != nil {
		return nil, errors.New("ua: Sign: timestamping is configured on the Signer; leave SignOptions.Timestamp nil")
	}
	if s.timestamp != nil {
		ts := *s.timestamp
		opts.Timestamp = &ts
	}
	return signWithEntry(ctx, key.entry, timestamper{discovery: key.discovery}, content, opts)
}
