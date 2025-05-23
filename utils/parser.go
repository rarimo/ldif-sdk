package utils

import (
	"encoding/pem"
	errs "errors"

	"github.com/rarimo/certificate-transparency-go/x509"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

const PemBlockType = "CERTIFICATE"

func ParsePemKeys(rawPemBlocks []string) ([]*x509.Certificate, error) {
	certsAmount := len(rawPemBlocks)
	certificates := make([]*x509.Certificate, len(rawPemBlocks))

	var err error
	for i := 0; i < certsAmount; i++ {
		certificates[i], err = ParsePemKey(rawPemBlocks[i])
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse pem key", logan.F{
				"block_number": i,
			})
		}
	}

	return certificates, nil
}

func ParsePemKey(rawPemKey string) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode([]byte(rawPemKey))
	if pemBlock == nil || pemBlock.Type != PemBlockType {
		return nil, errors.From(errors.New("failed to decode a pem block"), logan.F{
			"pem_block": rawPemKey,
		})
	}

	parsedPem, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil && !errs.As(err, &x509.NonFatalErrors{}) {
		return nil, errors.Wrap(err, "failed to parse certificate", logan.F{
			"pem_block": rawPemKey,
		})
	}

	return parsedPem, nil
}

func To32Bytes(arr []byte) []byte {
	if len(arr) >= 32 {
		return arr
	}

	res := make([]byte, 32-len(arr))
	return append(res, arr...)
}

func ParseCertificatesCollection(data []byte) ([]*x509.Certificate, error) {
	certificates := make([]*x509.Certificate, 0)

	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil && !errs.As(err, &x509.NonFatalErrors{}) {
			return nil, errors.Wrap(err, "failed to parse certificate")
		}

		certificates = append(certificates, cert)
	}

	return certificates, nil
}
