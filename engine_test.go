package execution

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rollkit/go-execution/types"
	"github.com/stretchr/testify/require"

	"github.com/docker/docker/pkg/archive"
	"github.com/testcontainers/testcontainers-go"
)

// createEthClient creates an Ethereum client for checking block information
func createEthClient(t *testing.T) *ethclient.Client {
	t.Helper()

	// Use the same ETH URL as in the tests
	ethClient, err := ethclient.Dial(TEST_ETH_URL)
	require.NoError(t, err, "Failed to create Ethereum client")

	return ethClient
}

// checkLatestBlock retrieves and returns the latest block height, hash, and transaction count using Ethereum API
func checkLatestBlock(t *testing.T, ctx context.Context) (uint64, common.Hash, int) {
	t.Helper()

	// Create an Ethereum client
	ethClient := createEthClient(t)
	defer ethClient.Close()

	// Get the latest block header
	header, err := ethClient.HeaderByNumber(ctx, nil) // nil means latest block
	if err != nil {
		t.Logf("Warning: Failed to get latest block header: %v", err)
		return 0, common.Hash{}, 0
	}

	blockNumber := header.Number.Uint64()
	blockHash := header.Hash()

	// Get the full block to count transactions
	block, err := ethClient.BlockByNumber(ctx, header.Number)
	if err != nil {
		t.Logf("Warning: Failed to get full block: %v", err)
		t.Logf("Latest block: height=%d, hash=%s, txs=unknown", blockNumber, blockHash.Hex())
		return blockNumber, blockHash, 0
	}

	fmt.Printf("tzdybal: %+v\n%+v\n", block, block.Header())

	txCount := len(block.Transactions())

	//t.Logf("Latest block: height=%d, hash=%s, txs=%d", blockNumber, blockHash.Hex(), txCount)
	return blockNumber, blockHash, txCount
}

func TestEngineExecution(t *testing.T) {
	allPayloads := make([][]types.Tx, 0) // Slice to store payloads from build to sync phase

	initialHeight := uint64(0)
	genesisHash := common.HexToHash(GENESIS_HASH)
	genesisTime := time.Now().UTC().Truncate(time.Second)
	genesisStateRoot := common.HexToHash(GENESIS_STATEROOT)
	rollkitGenesisStateRoot := types.Hash(genesisStateRoot[:])

	t.Run("Build chain", func(tt *testing.T) {
		jwtSecret := setupTestRethEngine(tt)

		executionClient, err := NewPureEngineExecutionClient(
			TEST_ENGINE_URL,
			jwtSecret,
			genesisHash,
			common.Address{},
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		stateRoot, gasLimit, err := executionClient.InitChain(ctx, genesisTime, initialHeight, CHAIN_ID)
		require.NoError(t, err)
		require.Equal(t, rollkitGenesisStateRoot, stateRoot)
		require.NotZero(t, gasLimit)

		prevStateRoot := rollkitGenesisStateRoot

		for blockHeight := initialHeight + 1; blockHeight <= 10; blockHeight++ {
			nTxs := int(blockHeight) + 10
			// randomly use no transactions
			if blockHeight == 4 {
				nTxs = 0
			}
			txs := make([]*ethTypes.Transaction, nTxs)
			for i := range txs {
				txs[i] = getRandomTransaction(t, 22000)
			}
			for i := range txs {
				submitTransaction(t, txs[i])
			}
			time.Sleep(1500 * time.Millisecond)

			payload, err := executionClient.GetTxs(ctx)
			require.NoError(tt, err)
			fmt.Println("Len:", len(payload))
			require.Len(tt, payload, nTxs+1)

			allPayloads = append(allPayloads, payload)

			fmt.Println(common.Bytes2Hex(prevStateRoot))

			// Check latest block before execution
			beforeHeight, beforeHash, beforeTxs := checkLatestBlock(tt, ctx)
			tt.Logf("Before ExecuteTxs (height %d): Latest block height=%d, hash=%s, txs=%d", blockHeight, beforeHeight, beforeHash.Hex(), beforeTxs)

			newStateRoot, maxBytes, err := executionClient.ExecuteTxs(ctx, payload, blockHeight, genesisTime, prevStateRoot)
			require.NoError(tt, err)
			require.NotZero(tt, maxBytes)

			// Check latest block after execution
			afterHeight, afterHash, afterTxs := checkLatestBlock(tt, ctx)
			tt.Logf("After ExecuteTxs (height %d): Latest block height=%d, hash=%s, txs=%d", blockHeight, afterHeight, afterHash.Hex(), afterTxs)

			if nTxs == 0 {
				require.Equal(tt, prevStateRoot, newStateRoot)
			} else {
				require.NotEqual(tt, prevStateRoot, newStateRoot)
			}
			prevStateRoot = newStateRoot
		}
	})

	// start new container and try to sync
	t.Run("Sync chain", func(tt *testing.T) {
		jwtSecret := setupTestRethEngine(t)

		executionClient, err := NewPureEngineExecutionClient(
			TEST_ENGINE_URL,
			jwtSecret,
			genesisHash,
			common.Address{},
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		stateRoot, gasLimit, err := executionClient.InitChain(ctx, genesisTime, initialHeight, CHAIN_ID)
		require.NoError(t, err)
		require.Equal(t, rollkitGenesisStateRoot, stateRoot)
		require.NotZero(t, gasLimit)
		//trash, err := executionClient.GetTxs(ctx)
		//require.NoError(t, err)
		//require.Len(t, trash, 1)

		prevStateRoot := rollkitGenesisStateRoot

		tt.Cleanup(func() {
			// Create docker client
			cli, err := testcontainers.NewDockerClient()
			require.NoError(tt, err)

			// Copy witness directory from container to host
			reader, _, err := cli.CopyFromContainer(context.Background(), "reth", "/root/.local/share/reth/1234/invalid_block_hooks/witness")
			require.NoError(tt, err)
			defer reader.Close()

			// Get current user's home directory
			homeDir, err := os.UserHomeDir()
			require.NoError(tt, err)
			destDir := filepath.Join(homeDir, "witness")

			// Create destination directory with current user permissions
			err = os.MkdirAll(destDir, 0755)
			require.NoError(tt, err)

			// Extract tar archive to destination with current user permissions
			err = archive.Untar(reader, destDir, &archive.TarOptions{
				NoLchown: true, // Don't try to change ownership
			})
			require.NoError(tt, err)
		})

		// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		// WARNING - the first payload is skipped - it would throw state root mismatch for whatever reason
		// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		for blockHeight := initialHeight + 1; blockHeight-initialHeight <= 10; blockHeight++ {
			payload := allPayloads[blockHeight-initialHeight-1]
			fmt.Println(common.Bytes2Hex(prevStateRoot))

			// Check latest block before execution
			beforeHeight, beforeHash, beforeTxs := checkLatestBlock(t, ctx)
			t.Logf("Before ExecuteTxs (height %d): Latest block height=%d, hash=%s, txs=%d", blockHeight, beforeHeight, beforeHash.Hex(), beforeTxs)

			newStateRoot, maxBytes, err := executionClient.ExecuteTxs(ctx, payload, blockHeight, genesisTime, prevStateRoot)
			require.NoErrorf(tt, err, "blockHeight: %d, nTxs: %d", blockHeight, len(payload)-1)
			require.NotZero(tt, maxBytes)

			// Check latest block after execution
			afterHeight, afterHash, afterTxs := checkLatestBlock(t, ctx)
			t.Logf("After ExecuteTxs (height %d): Latest block height=%d, hash=%s, txs=%d", blockHeight, afterHeight, afterHash.Hex(), afterTxs)

			if len(payload)-1 == 0 {
				require.Equal(tt, prevStateRoot, newStateRoot)
			} else {
				require.NotEqual(tt, prevStateRoot, newStateRoot)
			}
			prevStateRoot = newStateRoot
		}
	})
}
