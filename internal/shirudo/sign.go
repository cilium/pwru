// SPDX-License-Identifier: Apache-2.0
/* Copyright Authors of Cilium */

package shirudo

import (
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf-sl/signable"
)

// The files shirudo genkey writes into its --keys-dir.
const (
	KeyFile  = "signing_key.pem"
	CertFile = "cert.der"
)

var oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

// Signer holds the ML-DSA-87 key of a shirudo operator and the certificate
// a target's .bpf keyring holds for it.
type Signer struct {
	key  *mldsa.PrivateKey
	cert *x509.Certificate
}

// LoadSigner reads the key and the certificate shirudo genkey wrote: a
// PKCS #8 key in PEM, and a certificate in DER or PEM.
func LoadSigner(keyPath, certPath string) (*Signer, error) {
	keyFile, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := parseKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyPath, err)
	}
	certFile, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(certFile); block != nil {
		certFile = block.Bytes
	}
	cert, err := x509.ParseCertificate(certFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certPath, err)
	}
	if !key.PublicKey().Equal(cert.PublicKey) {
		return nil, fmt.Errorf("%s is not the certificate of %s", certPath, keyPath)
	}
	return &Signer{key: key, cert: cert}, nil
}

// LoadSignerDir reads the key and the certificate from a shirudo
// --keys-dir.
func LoadSignerDir(dir string) (*Signer, error) {
	return LoadSigner(filepath.Join(dir, KeyFile), filepath.Join(dir, CertFile))
}

// parseKey takes the key in every form OpenSSL writes one. crypto/x509
// refuses the form OpenSSL 3.5 writes by default, the seed together with
// the key expanded from it, of which a signer needs only the seed.
func parseKey(file []byte) (*mldsa.PrivateKey, error) {
	block, _ := pem.Decode(file)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PKCS #8 private key in PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		mk, ok := key.(*mldsa.PrivateKey)
		if !ok || mk.PublicKey().Parameters() != mldsa.MLDSA87() {
			return nil, fmt.Errorf("a %T key is no ML-DSA-87 key, the only one shirudo takes", key)
		}
		return mk, nil
	}

	var pkcs8 struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if rest, err := asn1.Unmarshal(block.Bytes, &pkcs8); err != nil || len(rest) != 0 {
		return nil, errors.New("malformed PKCS #8 private key")
	}
	if !pkcs8.Algo.Algorithm.Equal(oidMLDSA87) {
		return nil, fmt.Errorf("key algorithm %s is not ML-DSA-87, the only one shirudo takes", pkcs8.Algo.Algorithm)
	}
	var both struct {
		Seed     []byte
		Expanded []byte
	}
	if rest, err := asn1.Unmarshal(pkcs8.PrivateKey, &both); err != nil || len(rest) != 0 {
		return nil, errors.New("ML-DSA-87 key holds no seed")
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), both.Seed)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA-87 seed: %w", err)
	}
	return key, nil
}

// sign makes the detached CMS signature the kernel verifies over the
// loader's instructions followed by its data. ML-DSA signs the content
// itself; the digest algorithm, SHA-512, only names one for the record.
func (s *Signer) sign(l *signable.Loader) error {
	return l.Sign(signable.SignOptions{
		Hash:        crypto.SHA512,
		Certificate: s.cert,
		PrivateKey:  s.key,
	})
}
