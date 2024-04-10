package mt

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rarimo/ldif-sdk/ldif"
	"github.com/rarimo/ldif-sdk/utils"
)

func TestBuildTree(t *testing.T) {
	ldif, err := ldif.FromFile("icao-list.ldif")
	if err != nil {
		t.Fatal(err)
	}

	certs, err := json.Marshal(ldif.ToPem())
	if err != nil {
		t.Fatal(err)
	}

	tree, err := BuildTree(certs)
	if err != nil {
		t.Fatal(err)
	}

	//0x565b64fe947e72459a76bffc39095f5c4c2378c850cfede36ca1fb50a5badb
	fmt.Println(tree.Root())
	incProof, err := tree.GenerateInclusionProof(ldif.ToPem()[40])
	if err != nil {
		t.Fatal(err)
	}

	var resProof proof
	err = json.Unmarshal(incProof, &resProof)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(buildRoot(resProof.Siblings, ldif.ToPem()[40]))

}

func buildRoot(siblings [][]byte, pemCert string) (string, error) {
	cert, err := utils.ParsePemKey(pemCert)
	if err != nil {
		return "", err
	}

	certHash, err := utils.HashCertificate(cert)
	if err != nil {
		return "", err
	}

	proofHash := mustPoseidon(certHash.Bytes()).Bytes()
	//mustPoseidon(certHash.Bytes())
	for _, sibling := range siblings {
		proofHash = hash(proofHash, sibling)
	}

	return hexutil.Encode(proofHash), nil
}
