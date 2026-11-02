package ua

import (
	"errors"
	"os"

	"github.com/amaneshi/crypto-dstu/internal/cert"
	"github.com/amaneshi/crypto-dstu/internal/keystore"
	"github.com/amaneshi/crypto-dstu/internal/tsp"
	"github.com/amaneshi/crypto-dstu/pkg/dstu4145"
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
	keys         []*keyEntry
	caCerts      []*cert.Certificate
	certificates []*cert.Certificate
	selectedKey  int
	keySelected  bool
	tspClients   []*tsp.Client
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
		b.keys = append(b.keys, &keyEntry{privateKey: priv})
	}
	b.certificates = append(b.certificates, parsedCerts...)
	b.matchCertificates()

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

// AddCert adds a discovery certificate and associates it with a matching key.
// It does not trust that certificate; use LoadCABundle for explicit trust anchors.
func (b *Box) AddCert(der []byte) error {
	der = keystore.MaybePEM(der)
	c, err := cert.ParseCertificate(der)
	if err != nil {
		return errors.New("ua: AddCert: " + err.Error())
	}
	b.certificates = append(b.certificates, c)
	b.matchCertificates()
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
	certs, err := cert.ParseCertificates(data)
	if err != nil {
		return errors.New("ua: LoadCABundle: " + err.Error())
	}
	b.caCerts = append(b.caCerts, certs...)
	b.certificates = append(b.certificates, certs...)
	b.matchCertificates()
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
	if b.keySelected {
		return b.keys[b.selectedKey], nil
	}
	if len(b.keys) != 1 {
		// A container may hold one signing key and a separate agreement key.
		// Select the sole signing identity; multiple signing identities remain
		// ambiguous and require explicit role selection.
		var signing *keyEntry
		for _, entry := range b.keys {
			if entry.signCert == nil {
				continue
			}
			if signing != nil {
				return nil, errors.New("ua: multiple keys loaded; select a role explicitly")
			}
			signing = entry
		}
		if signing != nil {
			return signing, nil
		}
		return nil, errors.New("ua: multiple keys loaded; select a role explicitly")
	}
	return b.keys[0], nil
}

// SelectKeyByRole selects exactly one key. An ambiguous or missing role fails.
func (b *Box) SelectKeyByRole(role string) error {
	b.keySelected = false
	index := -1
	for i, e := range b.keys {
		if e.role == cert.Role(role) {
			if index >= 0 {
				return errors.New("ua: ambiguous key role")
			}
			index = i
		}
	}
	if index < 0 {
		return errors.New("ua: key role not found")
	}
	b.selectedKey = index
	b.keySelected = true
	return nil
}

func (b *Box) matchCertificates() {
	for _, entry := range b.keys {
		for _, c := range b.certificates {
			if cert.VerifyCertPKMatch(c, entry.privateKey) != nil {
				continue
			}
			if cert.CheckSigningUsage(c) == nil {
				entry.signCert = c
				entry.role = cert.DetectRole(c)
			}
			if cert.CheckEncryptionUsage(c) == nil {
				entry.cryptCert = c
			}
		}
	}
}
