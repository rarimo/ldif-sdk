package mt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/rarimo/ldif-sdk/utils"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type TreapTree struct {
	mTree certTree
}

// BuildTree builds a new dynamic Merkle tree with treap data structure
// from raw pem X.509 certificates array marshalled in JSON
func BuildTree(elements []byte) (*TreapTree, error) {
	pemKeys := make([]string, 0)
	if err := json.Unmarshal(elements, &pemKeys); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal raw pem keys")
	}

	certificates, err := utils.ParsePemKeys(pemKeys)
	if err != nil {
		return nil, errors.Wrap(err, "failed parse raw pem elements")
	}

	mTree := certTree{
		tree: nil,
	}

	mTree.tree, err = mTree.BuildTree(certificates)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build tree")
	}

	return &TreapTree{
		mTree: mTree,
	}, nil
}

// BuildFromRaw builds a new dynamic Merkle tree with treap data structure tree from raw data,
// directly hashing the leaves. It is assumed to use 256|384|512 byte public keys as input.
func BuildFromRaw(leaves []string) (*TreapTree, error) {
	mTree := certTree{
		tree: nil,
	}

	_, err := mTree.BuildFromLeaves(leaves)
	if err != nil {
		return nil, fmt.Errorf("build from leaves: %w", err)
	}

	return &TreapTree{
		mTree: mTree,
	}, nil
}

// BuildFromCosmos builds a new dynamic Merkle tree with treap data structure by getting elements
// directly from the Cosmos
func BuildFromCosmos() (*TreapTree, error) {
	//TODO: implement me!
	return nil, nil
}

// Root returns merkle tree root, if there is no tree empty string returned
func (it *TreapTree) Root() string {
	if it.mTree.tree == nil {
		return ""
	}

	return hex.EncodeToString(it.mTree.tree.MerkleRoot())
}

// IsExists checks if the tree exists
func (it *TreapTree) IsExists() bool {
	if it.mTree.tree != nil {
		return true
	}

	return false
}

// GenerateInclusionProof generates inclusion proof for the given pem certificate,
// returns marshalled inclusion proof
func (it *TreapTree) GenerateInclusionProof(rawPemCert string) ([]byte, error) {
	cert, err := utils.ParsePemKey(rawPemCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pem key: %w", err)
	}

	proof, err := it.mTree.GenInclusionProof(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to generate inclusion proof: %w", err)
	}

	hashes := make([]string, len(proof))
	for i, hash := range proof {
		hashes[i] = hex.EncodeToString(hash)
	}

	marshaledProof, err := json.Marshal(hashes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal proof hashes %v: %w", hashes, err)
	}

	return marshaledProof, nil
}
