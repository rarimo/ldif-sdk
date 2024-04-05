package mt

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/rarimo/ldif-sdk/utils"
	"github.com/wealdtech/go-merkletree/v2"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type IncrementalTree struct {
	mTree certTree
}

// BuildTree builds a new incremental tree from raw pem X.509
// certificates array marshalled in JSON in string type
func BuildTree(elements string) (*IncrementalTree, error) {
	pemKeys := make([]string, 0)
	if err := json.Unmarshal([]byte(elements), &pemKeys); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal raw pem keys")
	}

	certificates, err := utils.ParsePemKeys(pemKeys)
	if err != nil {
		return nil, errors.Wrap(err, "failed parse raw pem elements")
	}

	mTree := certTree{
		poseidon: NewPoseidon(),
		tree:     nil,
	}

	mTree.tree, err = mTree.BuildTree(certificates)
	if err != nil {
		return nil, errors.Wrap(err, "failed to build tree")
	}

	return &IncrementalTree{
		mTree: mTree,
	}, nil
}

// BuildFromRaw builds a new incremental tree from raw data, directly hashing the
// leaves. It is assumed to use 256|384|512 byte public keys as input.
func BuildFromRaw(leaves []string) (*IncrementalTree, error) {
	mTree := certTree{
		poseidon: NewPoseidon(),
		tree:     nil,
	}

	_, err := mTree.BuildFromLeaves(leaves)
	if err != nil {
		return nil, fmt.Errorf("build from leaves: %w", err)
	}

	return &IncrementalTree{
		mTree: mTree,
	}, nil
}

// Root returns merkle tree root, if there is no tree empty string returned
func (it *IncrementalTree) Root() string {
	if it.mTree.tree == nil {
		return ""
	}

	return hex.EncodeToString(it.mTree.tree.Root())
}

// IsExists checks if the tree exists
func (it *IncrementalTree) IsExists() bool {
	if it.mTree.tree != nil {
		return true
	}

	return false
}

// GenerateInclusionProof generates inclusion proof for the given pem certificate,
// returns marshalled inclusion proof
func (it *IncrementalTree) GenerateInclusionProof(rawPemCert string) ([]byte, error) {
	cert, err := utils.ParsePemKey(rawPemCert)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse pem key")
	}

	proof, err := it.mTree.GenInclusionProof(cert)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate inclusion proof")
	}

	res, err := json.Marshal(newInclusionProof(proof))
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal proof")
	}

	return res, nil
}

type inclusionProof struct {
	Hashes []string `json:"hashes"`
	Index  uint64   `json:"index"`
}

func newInclusionProof(proof *merkletree.Proof) *inclusionProof {
	hashes := make([]string, len(proof.Hashes))
	for i, hash := range proof.Hashes {
		hashes[i] = hex.EncodeToString(hash)
	}

	return &inclusionProof{
		Hashes: hashes,
		Index:  proof.Index,
	}
}
