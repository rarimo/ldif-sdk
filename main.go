package ldif

import (
	"encoding/base64"
	"os"
	"regexp"
	"strings"

	"github.com/rarimo/certificate-transparency-go/asn1"
	"github.com/rarimo/certificate-transparency-go/x509"

	"github.com/github/smimesign/ietf-cms/protocol"
)

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     SignedData `asn1:"explicit,tag:0"`
}

type SignedData struct {
	Version          int
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContInfo    EncapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"set,optional,tag:0"`
	CRLS             []asn1.RawValue `asn1:"set,optional,tag:1"`
}

type AlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
	Params    asn1.RawValue `asn1:"optional"`
}

type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"`
}

type CscaMasterList struct {
	Version  int
	CertList []asn1.RawValue `asn1:"set"`
}

func ExtractCSCAMasterListsFromLDIF(fileName string) ([]*CscaMasterList, error) {
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		return nil, err
	}

	ldifData := make([]byte, fileInfo.Size())
	ldifFile, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer ldifFile.Close()

	_, err = ldifFile.Read(ldifData)
	if err != nil {
		return nil, err
	}

	re, err := regexp.Compile(`(?s)pkdMasterListContent:: (.*?)\n\n`)
	if err != nil {
		return nil, err
	}

	dirtyB64bers := re.FindAllStringSubmatch(string(ldifData), -1)

	masterLists := make([]*CscaMasterList, len(dirtyB64bers))
	for i, dirtyB64ber := range dirtyB64bers {
		clearB64ber := strings.ReplaceAll(dirtyB64ber[1], "\n ", "")
		berData, err := base64.StdEncoding.DecodeString(clearB64ber)
		if err != nil {
			return nil, err
		}

		derData, err := protocol.BER2DER(berData)
		if err != nil {
			return nil, err
		}

		var content ContentInfo
		_, err = asn1.Unmarshal(derData, &content)
		if err != nil {
			return nil, err
		}

		var cscaMasterList CscaMasterList
		_, err = asn1.Unmarshal(content.Content.EncapContInfo.EContent, &cscaMasterList)
		if err != nil {
			return nil, err
		}

		masterLists[i] = &cscaMasterList
	}
	return masterLists, nil
}

func MasterList2x509(masterList CscaMasterList) ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(masterList.CertList))
	for i, derCertData := range masterList.CertList {
		cert, err := x509.ParseCertificate(derCertData.FullBytes)
		if _, ok := err.(x509.NonFatalErrors); err != nil && !ok {
			return nil, err
		}

		certs[i] = cert
	}
	return certs, nil
}
