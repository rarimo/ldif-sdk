package utils

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/ethereum/go-ethereum/common/hexutil"
	cosmos "github.com/rarimo/ldif-sdk/cosmos/pkg/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

func NewGRPCClient(addr string, isSecure bool) (*grpc.ClientConn, error) {
	creds := grpc.WithTransportCredentials(insecure.NewCredentials())
	if isSecure {
		creds = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13,
		}))
	}

	grpcClient, err := grpc.Dial(addr, creds, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:    10 * time.Second, // wait time before ping if no activity
		Timeout: 20 * time.Second, // ping timeout
	}))
	if err != nil {
		return nil, fmt.Errorf("failed to dial with grpc client %s: %w", addr, err)
	}

	return grpcClient, nil
}

func FetchHashLeavesFromCosmos(client cosmos.QueryClient) ([][]byte, error) {
	var (
		limit  = uint64(100)
		offset = uint64(0)
		leaves = make([][]byte, 0)
	)

	for {
		resp, err := client.Tree(context.Background(), &cosmos.QueryTreeRequest{
			Pagination: &query.PageRequest{
				CountTotal: true,
				Limit:      limit,
				Offset:     offset,
			},
		}, grpc.EmptyCallOption{})
		if err != nil {
			return nil, fmt.Errorf("failed to query tree: %w", err)
		}

		for _, node := range resp.Tree {
			bytesKey, err := hexutil.Decode(node.Key)
			if err != nil {
				return nil, fmt.Errorf("failed to decode key %s: %w", node.Key, err)
			}

			leaves = append(leaves, bytesKey)
		}

		if uint64(len(leaves)) == resp.Pagination.Total {
			break
		}

		offset += limit
	}

	return leaves, nil
}
