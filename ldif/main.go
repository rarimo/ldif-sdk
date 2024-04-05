package ldif

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/rarimo/certificate-transparency-go/asn1"
	"github.com/rarimo/certificate-transparency-go/x509"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type LDIF interface {
}

type ldif struct {
	rawData [][]byte
}

func New(filename string) (LDIF, error) {
	rawData, err := os.ReadFile(filename)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read file", logan.F{
			"filename": filename,
		})
	}

	certificates, err := ldifDecode(rawData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode ")
	}

	return &ldif{
		rawData: rawData,
	}, nil
}

type CSCAMasterList struct {
	Version  int
	CertList []asn1.RawValue `asn1:"set"`
}

func decodeContent(ldifData []byte) ([][]byte, error) {
	re, err := regexp.Compile(`(?s)pkdMasterListContent:: (.*?)\n\n`)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compile regexp")
	}

	dirtyData := re.FindAllStringSubmatch(string(ldifData), -1)

	ldifRawData := make([][]byte, len(dirtyData))
	for i, entry := range dirtyData {
		dataB64 := strings.ReplaceAll(entry[1], "\n ", "")
		data, err := base64.StdEncoding.DecodeString(dataB64)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode MasterListContent")
		}
		ldifRawData[i] = data
	}
	return ldifRawData, nil
}

func ExtractMasterLists(rawData [][]byte) ([]CSCAMasterList, error) {
	mls := make([]CSCAMasterList, len(rawData))
	for i, entry := range rawData {
		ci, err := protocol.ParseContentInfo(entry)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse ContentInfo")
		}

		signedData, err := ci.SignedDataContent()
		if err != nil {
			return nil, errors.Wrap(err, "failed to extract SignedData content")
		}

		encapData, err := signedData.EncapContentInfo.EContentValue()
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse encapsulated content")
		}

		var cscaMasterList CSCAMasterList
		_, err = asn1.Unmarshal(encapData, &cscaMasterList)
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse CSCAMasterList")
		}

		mls[i] = cscaMasterList
	}

	return mls, nil
}

func MasterListToX509(masterList CSCAMasterList) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(masterList.CertList))
	for i, derCertData := range masterList.CertList {
		cert, err := x509.ParseCertificate(derCertData.FullBytes)
		if _, ok := err.(x509.NonFatalErrors); err != nil && !ok {
			return nil, errors.Wrap(err, "failed to parse Certificate")
		}

		certs[i] = cert
	}
	return certs, nil
}

func LDIFToX509(fileName string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	data, err := os.ReadFile(fileName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read file")
	}

	rawLDIFData, err := ldifDecode(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode ldif data")
	}

	masterLists, err := ExtractMasterLists(rawLDIFData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract master lists")
	}

	for _, masterList := range masterLists {
		mlCerts, err := MasterListToX509(masterList)
		if err != nil {
			return nil, errors.Wrap(err, "failed extract certificates from master list")
		}
		certs = append(certs, mlCerts...)
	}

	return certs, nil
}

func LDIFToPEM(fileName string) ([]string, error) {
	certs, err := LDIFToX509(fileName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get certificates")
	}
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

func LDIFToX509Reader(reader io.Reader) ([]*x509.Certificate, error) {
	buf := &bytes.Buffer{}
	_, err := buf.ReadFrom(reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read")
	}
	data := buf.Bytes()

	rawLDIFData, err := ldifDecode(data)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode ldif data")
	}

	masterLists, err := ExtractMasterLists(rawLDIFData)
	if err != nil {
		return nil, errors.Wrap(err, "failed to extract master lists")
	}

	var certs []*x509.Certificate
	for _, masterList := range masterLists {
		mlCerts, err := MasterListToX509(masterList)
		if err != nil {
			return nil, errors.Wrap(err, "failed extract certificates from master list")
		}
		certs = append(certs, mlCerts...)
	}

	return certs, nil
}

func LDIFToPEMReader(reader io.Reader) ([]string, error) {
	certs, err := LDIFToX509Reader(reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get certificates")
	}
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
