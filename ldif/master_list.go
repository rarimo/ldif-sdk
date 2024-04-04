package ldif

import (
	"errors"
	"fmt"

	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/rarimo/certificate-transparency-go/asn1"
	"github.com/rarimo/certificate-transparency-go/x509"
)

// CSCAMasterList represents a master list of Country Signing Certificate
// Authority (CSCA). See https://pkddownloadsg.icao.int/ for more info.
type CSCAMasterList struct {
	Version  int
	CertList []asn1.RawValue `asn1:"set"`
}

// ExtractMasterLists extracts CSCA master lists from raw LDIF data
func ExtractMasterLists(rawData [][]byte) ([]CSCAMasterList, error) {
	mls := make([]CSCAMasterList, len(rawData))
	for i, entry := range rawData {
		ci, err := protocol.ParseContentInfo(entry)
		if err != nil {
			return nil, fmt.Errorf("parse content info: %w", err)
		}

		signedData, err := ci.SignedDataContent()
		if err != nil {
			return nil, fmt.Errorf("extract signed data content: %w", err)
		}

		encapData, err := signedData.EncapContentInfo.EContentValue()
		if err != nil {
			return nil, fmt.Errorf("parse encapsulated content: %w", err)
		}

		var list CSCAMasterList
		_, err = asn1.Unmarshal(encapData, &list)
		if err != nil {
			return nil, fmt.Errorf("unmarshal ASN.1 master list: %w", err)
		}

		mls[i] = list
	}

	return mls, nil
}

// ToX509 converts to X.509 certificates, ignoring x509.NonFatalErrors
func (ml CSCAMasterList) ToX509() ([]*x509.Certificate, error) {
	certs := make([]*x509.Certificate, len(ml.CertList))

	for i, derCertData := range ml.CertList {
		cert, err := x509.ParseCertificate(derCertData.FullBytes)
		if err != nil && !errors.As(err, &x509.NonFatalErrors{}) {
			return nil, fmt.Errorf("parse x509 certificate: %w", err)
		}

		certs[i] = cert
	}

	return certs, nil
}
