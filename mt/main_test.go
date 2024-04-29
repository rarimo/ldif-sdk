package mt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/rarimo/ldif-sdk/ldif"
	"github.com/rarimo/ldif-sdk/utils"
	"github.com/stretchr/testify/assert"
)

const (
	expectedRoot   = "0x0bb55cd80542e0a6dfc0347c56c5fe6d7eb7bc844cab709afbd082aa94d58077"
	RarimoGRPC     = "localhost:9090"
	ldifPath       = "icao-list.ldif"
	masterListPath = "masterlist.pem"
)

func TestFromCollection(t *testing.T) {
	data, err := os.ReadFile(masterListPath)
	if err != nil {
		t.Fatal(fmt.Errorf("reading pem file %w", err))
	}

	tree, err := BuildTreeFromCollection(data)
	if err != nil {
		t.Fatal(fmt.Errorf("building tree %w", err))
	}

	assert.Equal(t, tree.Root(), "0x0bb55cd80542e0a6dfc0347c56c5fe6d7eb7bc844cab709afbd082aa94d58077")
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

	assert.Equal(t, tree.Root(), expectedRoot)
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

	assert.Equal(t, tree.Root(), expectedRoot)
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
	assert.Equal(t, tree.Root(), "0x27e82c55bfbeba5ddb1b741a129ed9c6f97220ee4f47b0a77fa7fb0c5f4c7a54")
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
	rawProof, err := tree.GenerateInclusionProof(pemToTest)
	if err != nil {
		t.Fatal(fmt.Errorf("genereting inclusion proof %w", err))
	}

	var incProof proof
	if err := json.Unmarshal(rawProof, &incProof); err != nil {
		t.Fatal(fmt.Errorf("unmarshalling proof %w", err))
	}

	recoveredRoot, err := buildRoot(pemToTest, incProof)
	if err != nil {
		t.Fatal(fmt.Errorf("building root from proof: %w", err))
	}

	assert.Equal(t, tree.Root(), recoveredRoot)
}

func buildRoot(input string, incProof proof) (string, error) {
	cert, err := utils.ParsePemKey(input)
	if err != nil {
		return "", err
	}

	certHash, err := utils.HashCertificate(cert)
	if err != nil {
		return "", err
	}

	calculated := certHash
	for i, sibling := range incProof.Siblings {
		if len(sibling) == 0 {
			continue
		}
		switch incProof.Order[i] {
		case SameHashOrder:
			calculated = MustPoseidon([][]byte{calculated, sibling}...)
		case ReverseHashOrder:
			calculated = MustPoseidon([][]byte{sibling, calculated}...)
		default:
			continue
		}
	}

	return fmt.Sprintf("0x%s", hex.EncodeToString(calculated)), nil
}
