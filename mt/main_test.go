package mt

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/cosmos/cosmos-sdk/types/query"
	cosmos "github.com/rarimo/ldif-sdk/cosmos/pkg/types"
	"github.com/rarimo/ldif-sdk/ldif"
	"github.com/rarimo/ldif-sdk/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

func Test(t *testing.T) {
	ldif, err := ldif.FromFile("icao-list.ldif")
	if err != nil {
		t.Fatal(err)
	}

	input, err := json.Marshal(ldif.ToPem())
	if err != nil {
		t.Fatal(err)
	}

	tree, err := BuildTree(input)
	if err != nil {
		t.Fatal(err)
	}

	include := ldif.ToPem()[150]
	rawProof, err := tree.GenerateInclusionProof(include)
	if err != nil {
		t.Fatal(err)
	}

	var incProof proof
	if err := json.Unmarshal(rawProof, &incProof); err != nil {
		t.Fatal(err)
	}

	fmt.Println(tree.Root())
	root, err := buildRoot(include, incProof)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(root)

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
		switch incProof.Order[i] {
		case SameHashOrder:
			calculated = MustPoseidon([][]byte{calculated, sibling}...)
		case ReverseHashOrder:
			calculated = MustPoseidon([][]byte{sibling, calculated}...)
		default:
			fmt.Println("lox")
			continue
		}
	}

	return fmt.Sprintf("0x%s", hex.EncodeToString(calculated)), nil
}

func TestCosmos(t *testing.T) {
	tree, err := BuildFromCosmos("localhost:9090", false)
	if err != nil {
		t.Fatal(err)
	}

	creds := grpc.WithTransportCredentials(insecure.NewCredentials())
	grpcClient, err := grpc.Dial("localhost:9090", creds, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:    10 * time.Second, // wait time before ping if no activity
		Timeout: 20 * time.Second, // ping timeout
	}))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := cosmos.NewQueryClient(grpcClient).Tree(context.Background(), &cosmos.QueryTreeRequest{
		Pagination: &query.PageRequest{
			//If we can fetch any tree with such key -> root is okay
			Key:   tree.mTree.tree.MerkleRoot(),
			Limit: 1,
		},
	}, grpc.EmptyCallOption{})
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(resp)

	fmt.Println(tree.Root())
}
