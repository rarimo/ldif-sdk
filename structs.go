package ldif

import "github.com/rarimo/certificate-transparency-go/asn1"

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

type CSCAMasterList struct {
	Version  int
	CertList []asn1.RawValue `asn1:"set"`
}

type LDIFRawData struct {
	CN   string
	Data []byte
}
