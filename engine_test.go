package execution

import (
	"context"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/rollkit/go-execution/types"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestEngineExecution(t *testing.T) {
	jwtSecret := setupTestRethEngine(t)

	initialHeight := uint64(0)
	genesisHash := common.HexToHash(GENESIS_HASH)
	genesisTime := time.Now().UTC().Truncate(time.Second)
	genesisStateRoot := common.HexToHash(GENESIS_STATEROOT)
	rollkitGenesisStateRoot := types.Hash(genesisStateRoot[:])

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

	previouseStateRoot := rollkitGenesisStateRoot

	for blockHeight := initialHeight; blockHeight <= 10; blockHeight++ {
		txs := make([]*ethTypes.Transaction, 10)
		for i := range txs {
			txs[i] = getRandomTransaction(t, 22000)
		}
		for i := range txs {
			submitTransaction(t, txs[i])
		}
		time.Sleep(1 * time.Second)

		payload, err := executionClient.GetTxs(ctx)
		require.NoError(t, err)
		require.Len(t, payload, len(txs)+1)

		newStateRoot, maxBytes, err := executionClient.ExecuteTxs(ctx, payload, blockHeight, genesisTime, previouseStateRoot)
		require.NoError(t, err)
		require.NotZero(t, maxBytes)
		require.NotEqual(t, previouseStateRoot, newStateRoot)
		previouseStateRoot = newStateRoot
	}
}
