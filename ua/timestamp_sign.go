package ua

import (
	"bytes"
	"context"
	"encoding/asn1"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/cms"
	"github.com/amaneshi/crypto-dstu/internal/oid"
	"github.com/amaneshi/crypto-dstu/internal/tsp"
)

// DefaultTSPURL is PrivatBank's qualified timestamp service, used when a
// timestamp is requested with no TimestampSignOptions.URLs, no Fetch callback
// and (for Box) no AddTSP endpoint. DPS accepts PRRO timestamps from any
// qualified trust-service provider, so one TSA can serve keys issued by every CA.
const DefaultTSPURL = "http://acsk.privatbank.ua/services/tsp/"

// TimestampRequest carries only an encoded RFC 3161 request containing the
// signature imprint and nonce. A fetch callback owns its endpoint/network policy.
type TimestampRequest struct{ DER []byte }

// TimestampSignOptions requests a verified signature timestamp before output.
// The endpoint is chosen in this order: Fetch, then URLs, then (Box only) the
// AddTSP endpoints, then DefaultTSPURL. RevocationOptions accepts only
// revocation settings; TSA trust is selected through TSARoots.
type TimestampSignOptions struct {
	// IncludeContentTimestamp also obtains an authenticated timestamp over the
	// original content and signs it as a content-time-stamp attribute.
	IncludeContentTimestamp bool
	// TSARoots are the trusted TSA anchors (DER). Box requires them. A Signer
	// accepts none: the token is then fully checked except for the path to a
	// trusted root (see NewSigner).
	TSARoots         [][]byte
	ImprintAlgorithm asn1.ObjectIdentifier // zero selects GOST 34.311
	Fetch            func(context.Context, TimestampRequest) ([]byte, error)
	// URLs are TSA endpoints (http or https), tried in order until one answers.
	URLs []string
	// AttemptTimeout bounds each endpoint attempt so a hung TSA leaves time
	// for the next URL. Zero: each attempt is bounded only by the context.
	AttemptTimeout    time.Duration
	RevocationOptions VerificationOptions

	// unanchored is set only by NewSigner when TSARoots is empty.
	unanchored bool
}

// validate checks the options shared by Box and Signer timestamp creation.
func (options TimestampSignOptions) validate() error {
	if len(options.TSARoots) == 0 && !options.unanchored {
		return errors.New("ua: timestamp creation requires explicit TSA trust roots")
	}
	if options.RevocationOptions.TimestampPolicy != TimestampIgnore || len(options.RevocationOptions.TSARoots) > 0 {
		return errors.New("ua: creation RevocationOptions must contain only revocation settings")
	}
	if options.unanchored && options.RevocationOptions.Revocation != RevocationDisabled {
		return errors.New("ua: TSA revocation checking requires TSARoots")
	}
	if options.AttemptTimeout < 0 {
		return errors.New("ua: negative timestamp AttemptTimeout")
	}
	for _, raw := range options.URLs {
		if err := validTSPURL(raw); err != nil {
			return err
		}
	}
	return nil
}

func validTSPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("ua: invalid TSP URL " + raw)
	}
	return nil
}

// timestamper requests and verifies timestamp tokens. clients are the TSP
// endpoints tried in order when TimestampSignOptions.Fetch is nil; discovery
// certificates may help build the TSA path but never become trust anchors.
type timestamper struct {
	clients   []*tsp.Client
	discovery []*cert.Certificate
}

// timestamper returns the Box's endpoints (or DefaultTSPURL) and discovery certificates.
func (b *Box) timestamper() timestamper {
	return timestamper{clients: b.timestampClients(), discovery: b.certificates}
}

func (ts timestamper) addSignatureTimestamp(ctx context.Context, document []byte, options TimestampSignOptions) ([]byte, error) {
	message, err := cms.ParseSigned(document)
	if err != nil {
		return nil, err
	}
	signature, err := message.SignatureBytes(0)
	if err != nil {
		return nil, err
	}
	token, err := ts.requestVerifiedTimestamp(ctx, signature, options)
	if err != nil {
		return nil, err
	}
	timestamped, err := cms.AttachSignatureTimestamp(document, token)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return timestamped, nil
}

func (ts timestamper) requestVerifiedTimestamp(ctx context.Context, data []byte, options TimestampSignOptions) ([]byte, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	verification, err := options.RevocationOptions.normalized()
	if err != nil {
		return nil, err
	}
	var roots []*cert.Certificate
	for _, der := range options.TSARoots {
		c, err := cert.ParseCertificate(bytes.Clone(der))
		if err != nil {
			return nil, err
		}
		roots = append(roots, c)
	}
	algorithm := options.ImprintAlgorithm
	if len(algorithm) == 0 {
		algorithm = oid.GOST34311
	}
	imprint, err := tsp.HashData(data, algorithm)
	if err != nil {
		return nil, err
	}
	request, err := tsp.NewRequest(imprint, algorithm)
	if err != nil {
		return nil, err
	}
	requestDER, err := request.Marshal()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var response *tsp.Response
	if options.Fetch != nil {
		der, err := options.Fetch(ctx, TimestampRequest{DER: bytes.Clone(requestDER)})
		if err != nil {
			return nil, fmt.Errorf("ua: fetch timestamp: %w", err)
		}
		response, err = tsp.ParseResponse(bytes.Clone(der))
		if err != nil {
			return nil, err
		}
	} else {
		clients := ts.clients
		if len(options.URLs) > 0 {
			clients = make([]*tsp.Client, 0, len(options.URLs))
			for _, raw := range options.URLs {
				clients = append(clients, tsp.NewClient(raw))
			}
		}
		var failures []error
		for _, client := range clients {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			response, err = sendAttempt(ctx, client, requestDER, options.AttemptTimeout)
			if err == nil {
				break
			}
			failures = append(failures, err)
		}
		if response == nil {
			return nil, errors.Join(failures...)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.unanchored {
		// Every token check except the path to a trusted root; revocation
		// checking is disabled for unanchored use (see validate).
		if _, err := tsp.VerifyResponseUnanchored(response, request, time.Now(), ts.discovery...); err != nil {
			return nil, err
		}
	} else {
		verified, err := tsp.VerifyResponse(response, request, roots, time.Now(), ts.discovery...)
		if err != nil {
			return nil, err
		}
		if _, err := checkChainRevocation(ctx, verified.Chain, verification); err != nil {
			return nil, err
		}
	}
	token, err := response.Token()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return token, nil
}

// timestampClients returns the configured TSP endpoints, or DefaultTSPURL.
func (b *Box) timestampClients() []*tsp.Client {
	if len(b.tspClients) > 0 {
		return b.tspClients
	}
	return []*tsp.Client{tsp.NewClient(DefaultTSPURL)}
}

// sendAttempt sends one request, bounded by timeout when it is positive.
func sendAttempt(ctx context.Context, client *tsp.Client, requestDER []byte, timeout time.Duration) (*tsp.Response, error) {
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	return client.SendContext(ctx, requestDER)
}
