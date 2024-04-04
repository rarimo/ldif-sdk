package ldif

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/rarimo/certificate-transparency-go/x509"
	"github.com/rarimo/ldif-sdk/utils"
)

// LDIFToX509 parses X.509 certificates from the provided LDIF file
func LDIFToX509(fileName string) ([]*x509.Certificate, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	return LDIFToX509Reader(file)
}

// LDIFToX509Reader is like LDIFToX509 but reads from io.Reader
func LDIFToX509Reader(r io.Reader) ([]*x509.Certificate, error) {
	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("read to buffer from reader: %w", err)
	}

	return ldifToX509(buf.Bytes())
}

func ldifToX509(rawData []byte) ([]*x509.Certificate, error) {
	rawLDIFData, err := ldifDecode(rawData)
	if err != nil {
		return nil, fmt.Errorf("decode ldif data: %w", err)
	}

	masterLists, err := ExtractMasterLists(rawLDIFData)
	if err != nil {
		return nil, fmt.Errorf("extract master lists: %w", err)
	}

	certs := make([]*x509.Certificate, 0, len(masterLists))
	for _, masterList := range masterLists {
		mlCerts, err := masterList.ToX509()
		if err != nil {
			return nil, fmt.Errorf("extract x509 certificates from master list: %w", err)
		}
		certs = append(certs, mlCerts...)
	}

	return certs, nil
}

func ldifDecode(ldifData []byte) ([][]byte, error) {
	var (
		re           = regexp.MustCompile(`(?s)pkdMasterListContent:: (.*?)\n\n`)
		dirtyData    = re.FindAllSubmatch(ldifData, -1)
		ldifRawData  = make([][]byte, len(dirtyData))
		newLineBytes = []byte("\n ")
	)

	for i, entry := range dirtyData {
		dataB64 := bytes.ReplaceAll(entry[1], newLineBytes, nil)
		ldifRawData[i] = make([]byte, base64.StdEncoding.DecodedLen(len(dataB64)))

		_, err := base64.StdEncoding.Decode(ldifRawData[i], dataB64)
		if err != nil {
			return nil, fmt.Errorf("decode MasterListContent: %w", err)
		}
	}

	return ldifRawData, nil
}

// LDIFToPEM converts certificates from LDIF file to PEM format
func LDIFToPEM(fileName string) ([]string, error) {
	certs, err := LDIFToX509(fileName)
	if err != nil {
		return nil, fmt.Errorf("parse certificates from LDIF: %w", err)
	}

	return x509ToPEM(certs)
}

// LDIFToPEMReader is like LDIFToPEM but reads from io.Reader
func LDIFToPEMReader(r io.Reader) ([]string, error) {
	certs, err := LDIFToX509Reader(r)
	if err != nil {
		return nil, fmt.Errorf("parse certificates from LDIF: %w", err)
	}

	return x509ToPEM(certs)
}

func x509ToPEM(certs []*x509.Certificate) ([]string, error) {
	pems := make([]string, len(certs))
	for i, cert := range certs {
		pemCert := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		pems[i] = string(pem.EncodeToMemory(&pemCert))
	}

	return pems, nil
}

// LDIFToPubKeys parses X.509 certificates from the provided LDIF file and
// returns their public keys. Duplicate keys are excluded from the result.
func LDIFToPubKeys(fileName string) ([][]byte, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	return LDIFToPubKeysReader(file)
}

// LDIFToPubKeysReader is like LDIFToPubKeys but reads from io.Reader
func LDIFToPubKeysReader(r io.Reader) ([][]byte, error) {
	certs, err := LDIFToX509Reader(r)
	if err != nil {
		return nil, fmt.Errorf("parse LDIF to x509: %w", err)
	}

	return utils.ExtractPubKeys(certs)
}
