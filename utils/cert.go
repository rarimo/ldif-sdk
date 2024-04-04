package utils

import (
	"crypto/rsa"

	"github.com/rarimo/certificate-transparency-go/x509"
)

func ExtractPubKeys(certs []*x509.Certificate) ([][]byte, error) {
	pubKeys := make([][]byte, 0, len(certs))
	pkMap := make(map[string]struct{}, len(certs)-1)

	for _, cert := range certs {
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			// FIXME @violog Handle ecdsa.PublicKey
			continue
		}

		// string() conversion is intended: as we only use it as a map key, encoding is not important
		if _, ok = pkMap[string(key.N.Bytes())]; ok {
			continue
		}

		pkMap[string(key.N.Bytes())] = struct{}{}
		pubKeys = append(pubKeys, key.N.Bytes())
	}

	return pubKeys, nil
}
