package ldif

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"cloud.google.com/go/storage"
	"github.com/rarimo/certificate-transparency-go/x509"
	"github.com/rarimo/ldif-sdk/utils"
	"google.golang.org/api/option"
)

const (
	downloadingTimeout = time.Second * 60
)

type LDIF interface {
	ToX509() []*x509.Certificate
	ToPem() []string
	RawPubKeys() ([][]byte, error)
}

type ldif struct {
	certificates []*x509.Certificate
}

// FromS3Bucket creates new LDIF instance from ICAO list downloaded from remote S3 (like Google Storage or Amazon S3)
func FromS3Bucket(ctx context.Context, bucketName string, fileName string) (LDIF, error) {
	client, err := storage.NewClient(ctx, option.WithoutAuthentication())
	if err != nil {
		return nil, fmt.Errorf("creating new storage client: %w", err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(ctx, downloadingTimeout)
	defer cancel()

	objReader, err := client.Bucket(bucketName).Object(fileName).NewReader(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading content %s from %s: %w", bucketName, fileName, err)
	}
	defer objReader.Close()

	return FromReader(objReader)
}

// FromFile creates new LDIF instance from file
func FromFile(filename string) (LDIF, error) {
	rawData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filename, err)
	}

	return NewLDIF(rawData)
}

// FromReader creates new LDIF instance from file
func FromReader(r io.Reader) (LDIF, error) {
	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("read to buffer from reader: %w", err)
	}

	return NewLDIF(buf.Bytes())
}

// NewLDIF creates new LDIF instance from raw bytes
func NewLDIF(data []byte) (LDIF, error) {
	certificates, err := ldifToX509(data)
	if err != nil {
		return nil, fmt.Errorf("converting raw content to x509: %w", err)
	}

	return &ldif{
		certificates: certificates,
	}, nil
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

func (l ldif) ToX509() []*x509.Certificate {
	return l.certificates
}

func (l ldif) ToPem() []string {
	pems := make([]string, len(l.certificates))
	for i, cert := range l.certificates {
		pemCert := pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		pems[i] = string(pem.EncodeToMemory(&pemCert))
	}

	return pems
}

func (l ldif) RawPubKeys() ([][]byte, error) {
	return utils.ExtractPubKeys(l.certificates)
}
