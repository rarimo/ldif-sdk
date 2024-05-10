package mt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/iden3/go-iden3-crypto/keccak256"
	"github.com/rarimo/ldif-sdk/ldif"
	"github.com/rarimo/ldif-sdk/utils"
	"github.com/stretchr/testify/assert"
)

const (
	expectedRoot   = "0x04cbc488474858754c9226bad06de40398c3b34b3c52285308c019f28011e87e"
	RarimoGRPC     = "localhost:9090"
	ldifPath       = "icao-list.ldif"
	masterListPath = "masterlist.pem"
)

func TestFromCollection(t *testing.T) {
	const expectedRoot = "0xca09a639ceafe2c7b3d37f1ddd78ae0b203332a3e7b180aa35435a0d3a8cd8c7"

	data, err := os.ReadFile(masterListPath)
	if err != nil {
		t.Fatal(fmt.Errorf("reading pem file %w", err))
	}

	tree, err := BuildTreeFromCollection(data)
	if err != nil {
		t.Fatal(fmt.Errorf("building tree %w", err))
	}

	assert.Equal(t, expectedRoot, fmt.Sprintf("0x%s", hex.EncodeToString(tree.Root())))
}

func TestFromRawX509(t *testing.T) {
	data, err := ldif.FromFile(ldifPath)
	if err != nil {
		t.Fatal(fmt.Errorf("reading LDIF file %w", err))
	}

	rawCertificates, err := json.Marshal(data.ToPem())
	if err != nil {
		t.Fatal(fmt.Errorf("marshalling certificates %w", err))
	}

	tree, err := BuildTreeFromMarshalled(rawCertificates)
	if err != nil {
		t.Fatal(fmt.Errorf("building tree %w", err))
	}

	assert.Equal(t, fmt.Sprintf("0x%s", hex.EncodeToString(tree.Root())), expectedRoot)
}

func TestFromRawPKs(t *testing.T) {
	data, err := ldif.FromFile(ldifPath)
	if err != nil {
		t.Fatal(fmt.Errorf("reading LDIF file %w", err))
	}

	pks, err := data.RawPubKeys()
	if err != nil {
		t.Fatal(fmt.Errorf("extracting public keys %w", err))
	}

	leaves := make([]string, len(pks))
	for i, pk := range pks {
		leaves[i] = string(pk)
	}

	tree, err := BuildFromRaw(leaves)
	if err != nil {
		t.Fatal(fmt.Errorf("building tree %w", err))
	}

	assert.Equal(t, fmt.Sprintf("0x%s", hex.EncodeToString(tree.Root())), expectedRoot)
}

// NOTE: TestFromCosmos will work only with connection to Rarimo gRPC
// with CSCA_ROOT_UPDATE proposal in order to have anything to build
// tree from.
func TestFromCosmos(t *testing.T) {
	tree, err := BuildFromCosmos(RarimoGRPC, false)
	if err != nil {
		t.Fatal(fmt.Errorf("failed to build tree from cosmos %w", err))
	}

	//Use your own root, that is stored on-chain
	assert.Equal(t, expectedRoot, fmt.Sprintf("0x%s", hex.EncodeToString(tree.Root())))
}

func TestVerifyProof(t *testing.T) {
	data, err := ldif.FromFile(ldifPath)
	if err != nil {
		t.Fatal(fmt.Errorf("reading LDIF file %w", err))
	}

	pems := data.ToPem()
	rawCertificates, err := json.Marshal(pems)
	if err != nil {
		t.Fatal(fmt.Errorf("marshalling certificates %w", err))
	}

	tree, err := BuildTreeFromMarshalled(rawCertificates)
	if err != nil {
		t.Fatal(fmt.Errorf("building tree %w", err))
	}

	pemToTest := pems[30]
	incProof, err := tree.GenerateInclusionProof(pemToTest)
	if err != nil {
		t.Fatal(fmt.Errorf("genereting inclusion proof %w", err))
	}

	recoveredRoot, err := buildRoot(pemToTest, *incProof)
	if err != nil {
		t.Fatal(fmt.Errorf("building root from proof: %w", err))
	}

	assert.Equal(t, fmt.Sprintf("0x%s", hex.EncodeToString(tree.Root())), recoveredRoot)
}

func buildRoot(input string, incProof Proof) (string, error) {
	cert, err := utils.ParsePemKey(input)
	if err != nil {
		return "", err
	}

	certHash, err := utils.HashCertificate(cert)
	if err != nil {
		return "", err
	}

	calculated := certHash
	for _, sibling := range incProof.Siblings {
		if len(sibling) == 0 {
			continue
		}

		if bytes.Compare(calculated, sibling) < 0 {
			calculated = keccak256.Hash(calculated, sibling)
		} else {
			calculated = keccak256.Hash(sibling, calculated)
		}
	}

	return fmt.Sprintf("0x%s", hex.EncodeToString(calculated)), nil
}
