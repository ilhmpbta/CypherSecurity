package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"
)

func GenerateKeypairAndCert(commonName string) (*rsa.PrivateKey, []byte, []byte, string, time.Time, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, nil, "", time.Time{}, fmt.Errorf("generate rsa key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, nil, "", time.Time{}, fmt.Errorf("marshal public key: %w", err)
	}

	sum := sha256.Sum256(pubDER)
	fingerprint := hex.EncodeToString(sum[:])

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.AddDate(10, 0, 0)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, "", time.Time{}, fmt.Errorf("create certificate: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, nil, "", time.Time{}, fmt.Errorf("marshal pkcs8: %w", err)
	}

	return priv, privDER, certDER, fingerprint, notAfter, nil
}

func ParsePublicKey(pubDER []byte) (*rsa.PublicKey, error) {
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return nil, fmt.Errorf("parse pkix public key: %w", err)
	}
	pubKey, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("keys: not an RSA public key")
	}
	return pubKey, nil
}
