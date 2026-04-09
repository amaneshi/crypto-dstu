package ua

import (
	"errors"
	"os"

	"crypto-dstu/internal/cert"
	"crypto-dstu/internal/keystore"
	"crypto-dstu/internal/tsp"
	"crypto-dstu/pkg/dstu4145"
)

// keyEntry holds a private key with its associated certificates (internal).
type keyEntry struct {
	privateKey *dstu4145.PrivateKey
	signCert   *cert.Certificate
	cryptCert  *cert.Certificate
	role       cert.Role
}

// Box is a stateful context that manages keys, certificates, CA list and TSP config.
type Box struct {
	keys       []*keyEntry
	caCerts    []*cert.Certificate
	tspClients []*tsp.Client
}

// NewBox creates an empty Box.
func NewBox() *Box {
	return &Box{}
}

// LoadKey auto-detects the key container format and loads keys+certs into the Box.
func (b *Box) LoadKey(data []byte, password string) error {
	result, err := keystore.Parse(data, password)
	if err != nil {
		// Try JKS with password (PrivatBank JKS stores encrypted key blobs)
		result, err = keystore.ParseJKSWithPassword(data, password)
		if err != nil {
			return errors.New("ua: LoadKey: " + err.Error())
		}
	}

	// Parse embedded certs
	var parsedCerts []*cert.Certificate
	var c *cert.Certificate
	for _, derBytes := range result.Certs {
		c, err = cert.ParseCertificate(derBytes)
		if err != nil {
			continue
		}
		parsedCerts = append(parsedCerts, c)
	}

	for _, priv := range result.Keys {
		entry := &keyEntry{privateKey: priv}
		// Match certs to this key
		for _, c := range parsedCerts {
			if cert.VerifyCertPKMatch(c, priv) == nil {
				if entry.signCert == nil {
					entry.signCert = c
					entry.cryptCert = c
				}
			}
		}
		if entry.signCert != nil {
			entry.role = cert.DetectRole(entry.signCert)
		}
		b.keys = append(b.keys, entry)
	}

	// Add any unmatched certs to caCerts pool
	b.caCerts = append(b.caCerts, parsedCerts...)

	return nil
}

// LoadKeyFile reads a key file from disk and calls LoadKey.
func (b *Box) LoadKeyFile(path string, password string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New("ua: LoadKeyFile: " + err.Error())
	}
	return b.LoadKey(data, password)
}

// AddCert parses a DER or PEM certificate and adds it to the CA pool.
func (b *Box) AddCert(der []byte) error {
	der = keystore.MaybePEM(der)
	c, err := cert.ParseCertificate(der)
	if err != nil {
		return errors.New("ua: AddCert: " + err.Error())
	}
	b.caCerts = append(b.caCerts, c)
	return nil
}

// AddCertFile reads a certificate file from disk and calls AddCert.
func (b *Box) AddCertFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New("ua: AddCertFile: " + err.Error())
	}
	return b.AddCert(data)
}

// LoadCABundle parses a DER or PEM certificate bundle (concatenated certs or PKCS#7 certs-only)
// and adds all found certificates to the CA pool.
func (b *Box) LoadCABundle(data []byte) error {
	data = keystore.MaybePEM(data)
	certs, err := cert.ParseCertificates(data)
	if err != nil {
		return errors.New("ua: LoadCABundle: " + err.Error())
	}
	b.caCerts = append(b.caCerts, certs...)
	return nil
}

// LoadCABundleFile reads a certificate bundle file from disk and calls LoadCABundle.
func (b *Box) LoadCABundleFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New("ua: LoadCABundleFile: " + err.Error())
	}
	return b.LoadCABundle(data)
}

// AddTSP registers a TSP server URL.
func (b *Box) AddTSP(url string) {
	b.tspClients = append(b.tspClients, tsp.NewClient(url))
}

// KeyByRole returns the index of the first key whose cert role matches the given string, or -1.
// Role values: "personal", "fop", "director", "stamp", "other".
func (b *Box) KeyByRole(role string) int {
	r := cert.Role(role)
	for i, e := range b.keys {
		if e.role == r {
			return i
		}
	}
	return -1
}

// UnprotectKey parses a key container and returns the raw private key as DER or PEM bytes.
// format must be "der" or "pem".
func UnprotectKey(data []byte, password string, format string) ([]byte, error) {
	result, err := keystore.Parse(data, password)
	if err != nil {
		result, err = keystore.ParseJKSWithPassword(data, password)
		if err != nil {
			return nil, errors.New("ua: UnprotectKey: " + err.Error())
		}
	}
	if len(result.Keys) == 0 {
		return nil, errors.New("ua: UnprotectKey: no private keys found in container")
	}
	var out []byte
	switch format {
	case "der":
		out, err = keystore.MarshalPrivateKeyDER(result.Keys[0])
		if err != nil {
			return nil, errors.New("ua: UnprotectKey: marshal DER: " + err.Error())
		}
	default:
		out, err = keystore.MarshalPrivateKeyPEM(result.Keys[0])
		if err != nil {
			return nil, errors.New("ua: UnprotectKey: marshal PEM: " + err.Error())
		}
	}
	return out, nil
}

// firstKey returns the first available keyEntry, or an error if none loaded.
func (b *Box) firstKey() (*keyEntry, error) {
	if len(b.keys) == 0 {
		return nil, errors.New("ua: no keys loaded")
	}
	return b.keys[0], nil
}
