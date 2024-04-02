package ldif

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/rarimo/certificate-transparency-go/asn1"
	"github.com/rarimo/certificate-transparency-go/x509"

	"github.com/github/smimesign/ietf-cms/protocol"
)

func ReadLDIF(fileName string) ([]LDIFRawData, error) {
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to get file stat: %w", err)
	}

	ldifFile, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer ldifFile.Close()

	ldifData := make([]byte, fileInfo.Size())
	_, err = ldifFile.Read(ldifData)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	re, err := regexp.Compile(`(?s)cn: (.+?)\n(?:objectClass:.*?\n)+?.*?pkdMasterListContent:: (.*?)\n\n`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regexp: %w", err)
	}

	dirtyLDIFData := re.FindAllStringSubmatch(string(ldifData), -1)
	ldifRawData := make([]LDIFRawData, len(dirtyLDIFData))
	for i, entry := range dirtyLDIFData {
		ldifRawData[i].CN = strings.ReplaceAll(entry[1], "\n ", "")

		dataB64 := strings.ReplaceAll(entry[2], "\n ", "")
		data, err := base64.StdEncoding.DecodeString(dataB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode MasterListContent: %w", err)
		}
		ldifRawData[i].Data = data
	}

	return ldifRawData, nil
}

func ReadLDIF2(fileName string) ([][]byte, error) {
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to get file stat: %w", err)
	}

	ldifFile, err := os.OpenFile(fileName, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer ldifFile.Close()

	ldifData := make([]byte, fileInfo.Size())
	_, err = ldifFile.Read(ldifData)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	re, err := regexp.Compile(`(?s)pkdMasterListContent:: (.*?)\n\n`)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regexp: %w", err)
	}

	dirtyLDIFData := re.FindAllStringSubmatch(string(ldifData), -1)
	ldifRawData := make([][]byte, len(dirtyLDIFData))
	for i, entry := range dirtyLDIFData {
		dataB64 := strings.ReplaceAll(entry[1], "\n ", "")
		data, err := base64.StdEncoding.DecodeString(dataB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode MasterListContent: %w", err)
		}
		ldifRawData[i] = data
	}

	return ldifRawData, nil
}

func ExtractMasterLists(rawData [][]byte) (mls []CSCAMasterList, err error) {
	mls = make([]CSCAMasterList, len(rawData))
	for i, entry := range rawData {
		derData, err := protocol.BER2DER(entry)
		if err != nil {
			return nil, err
		}

		var content ContentInfo
		_, err = asn1.Unmarshal(derData, &content)
		if err != nil {
			return nil, err
		}

		var cscaMasterList CSCAMasterList
		_, err = asn1.Unmarshal(content.Content.EncapContInfo.EContent, &cscaMasterList)
		if err != nil {
			return nil, err
		}

		mls[i] = cscaMasterList
	}

	return mls, nil
}

func MasterList2x509(masterList CSCAMasterList) ([]*x509.Certificate, error) {
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

func ExtractCertsFromLDIF(fileName string) ([][]*x509.Certificate, error) {
	data, err := ReadLDIF2(fileName)
	if err != nil {
		return nil, err
	}

	masterLists, err := ExtractMasterLists(data)
	if err != nil {
		return nil, err
	}

	certificates := make([][]*x509.Certificate, len(masterLists))
	for i, masterList := range masterLists {
		mlCerts, err := MasterList2x509(masterList)
		if err != nil {
			return nil, err
		}

		certificates[i] = mlCerts
	}

	return certificates, nil
}
