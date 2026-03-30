package ua

import (
	"errors"
	"os"

	"crypto-dstu/cert"
	"crypto-dstu/dstu4145"
	"crypto-dstu/keystore"
	"crypto-dstu/tsp"
)

// KeyEntry holds a private key with its associated certificates.
type KeyEntry struct {
	PrivateKey *dstu4145.PrivateKey
	SignCert   *cert.Certificate // signing certificate
	CryptCert  *cert.Certificate // encryption certificate (may be same as SignCert)
	Role       cert.Role
}

// Box is a stateful context that manages keys, certificates, CA list and TSP config.
type Box struct {
	Keys       []*KeyEntry
	CACerts    []*cert.Certificate
	TSPClients []*tsp.Client
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
	for _, derBytes := range result.Certs {
		c, err := cert.ParseCertificate(derBytes)
		if err != nil {
			continue
		}
		parsedCerts = append(parsedCerts, c)
	}

	for _, priv := range result.Keys {
		entry := &KeyEntry{PrivateKey: priv}
		// Match certs to this key
		for _, c := range parsedCerts {
			if cert.VerifyCertPKMatch(c, priv) == nil {
				if entry.SignCert == nil {
					entry.SignCert = c
					entry.CryptCert = c
				}
			}
		}
		if entry.SignCert != nil {
			entry.Role = cert.DetectRole(entry.SignCert)
		}
		b.Keys = append(b.Keys, entry)
	}

	// Add any unmatched certs to CACerts pool
	for _, c := range parsedCerts {
		b.CACerts = append(b.CACerts, c)
	}

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
	b.CACerts = append(b.CACerts, c)
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

// AddTSP registers a TSP server URL.
func (b *Box) AddTSP(url string) {
	b.TSPClients = append(b.TSPClients, tsp.NewClient(url))
}

// KeyByRole returns the first KeyEntry whose cert role matches, or nil.
func (b *Box) KeyByRole(role cert.Role) *KeyEntry {
	for _, e := range b.Keys {
		if e.Role == role {
			return e
		}
	}
	return nil
}

// firstKey returns the first available KeyEntry, or an error if none loaded.
func (b *Box) firstKey() (*KeyEntry, error) {
	if len(b.Keys) == 0 {
		return nil, errors.New("ua: no keys loaded")
	}
	return b.Keys[0], nil
}
