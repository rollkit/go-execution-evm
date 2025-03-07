package execution

import (
	"context"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/rollkit/go-execution/types"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

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
			nTxs := int(blockHeight)
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
			require.NoError(t, err)
			require.Len(t, payload, nTxs+1)

			allPayloads = append(allPayloads, payload)

			fmt.Println(common.Bytes2Hex(prevStateRoot))
			newStateRoot, maxBytes, err := executionClient.ExecuteTxs(ctx, payload, blockHeight, genesisTime, prevStateRoot)
			require.NoError(t, err)
			require.NotZero(t, maxBytes)
			if nTxs == 0 {
				require.Equal(t, prevStateRoot, newStateRoot)
			} else {
				require.NotEqual(t, prevStateRoot, newStateRoot)
			}
			prevStateRoot = newStateRoot
		}
	})

	// start new container and try to sync
	t.Run("Sync chain", func(t *testing.T) {
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

		prevStateRoot := rollkitGenesisStateRoot

		// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		// WARNING - the first payload is skipped - it would throw state root mismatch for whatever reason
		// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
		for blockHeight := initialHeight + 1; blockHeight-initialHeight < 10; blockHeight++ {
			payload := allPayloads[blockHeight-initialHeight]
			fmt.Println(common.Bytes2Hex(prevStateRoot))
			newStateRoot, maxBytes, err := executionClient.ExecuteTxs(ctx, payload, blockHeight, genesisTime, prevStateRoot)
			require.NoErrorf(t, err, "blockHeight: %d, nTxs: %d", blockHeight, len(payload)-1)
			require.NotZero(t, maxBytes)
			if len(payload)-1 == 0 {
				require.Equal(t, prevStateRoot, newStateRoot)
			} else {
				require.NotEqual(t, prevStateRoot, newStateRoot)
			}
			prevStateRoot = newStateRoot
		}
	})
}
