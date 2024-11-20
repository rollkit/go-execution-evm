package execution

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/rollkit/go-execution-evm/mocks"
	proxy_json_rpc "github.com/rollkit/go-execution/proxy/jsonrpc"
	execution_types "github.com/rollkit/go-execution/types"
	"github.com/stretchr/testify/require"
)

// Helper function to generate a test JWT secret
func generateTestJWTSecret() string {
	// Generate a random 32-byte hex string for testing
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	return hex.EncodeToString(secret)
}

func TestEngineAPIExecutionClient_InitChain(t *testing.T) {
	mockEngine := mocks.NewMockEngineAPI(t)
	defer mockEngine.Close()

	mockEth := mocks.NewMockEthAPI(t)
	defer mockEth.Close()

	jwtSecret := generateTestJWTSecret()
	client, err := NewEngineAPIExecutionClient(
		&proxy_json_rpc.Config{},
		mockEth.URL,
		mockEngine.URL,
		jwtSecret,
		common.Hash{},
		common.Address{},
	)
	require.NoError(t, err)

	genesisTime := time.Now().UTC().Truncate(time.Second)
	initialHeight := uint64(0)
	chainID := "11155111" // sepolia chain id

	ctx := context.Background()
	stateRoot, gasLimit, err := client.InitChain(ctx, genesisTime, initialHeight, chainID)
	require.NoError(t, err)

	mockStateRoot := common.HexToHash("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	expectedStateRoot := execution_types.Hash(mockStateRoot[:])

	require.Equal(t, expectedStateRoot, stateRoot)
	require.Equal(t, uint64(1000000), gasLimit)

	lastCall := mockEngine.GetLastForkchoiceUpdated()
	require.NotNil(t, lastCall)
	require.Equal(t, common.Hash{}.Hex(), lastCall.HeadBlockHash)
	require.Equal(t, common.Hash{}.Hex(), lastCall.SafeBlockHash)
	require.Equal(t, common.Hash{}.Hex(), lastCall.FinalizedBlockHash)
}

func TestEngineAPIExecutionClient_ExecuteTxs(t *testing.T) {
	mockEngine := mocks.NewMockEngineAPI(t)
	defer mockEngine.Close()

	mockEth := mocks.NewMockEthAPI(t)
	defer mockEth.Close()

	jwtSecret := generateTestJWTSecret()
	client, err := NewEngineAPIExecutionClient(
		&proxy_json_rpc.Config{},
		mockEth.URL,
		mockEngine.URL,
		jwtSecret,
		common.Hash{},
		common.Address{},
	)
	require.NoError(t, err)

	blockHeight := uint64(1)
	timestamp := time.Now().UTC().Truncate(time.Second)

	prevStateRoot := execution_types.Hash(common.Hex2Bytes("111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"))

	testTxBytes, err := types.NewTransaction(1, common.Address{}, big.NewInt(0), 1000, big.NewInt(875000000), nil).MarshalBinary()
	require.NoError(t, err)
	testTx := execution_types.Tx(testTxBytes)

	ctx := context.Background()
	stateRoot, gasUsed, err := client.ExecuteTxs(
		ctx,
		[]execution_types.Tx{testTx},
		blockHeight,
		timestamp,
		prevStateRoot,
	)
	require.NoError(t, err)

	lastCall := mockEngine.GetLastForkchoiceUpdated()
	require.NotNil(t, lastCall)
	require.Equal(t, common.BytesToHash(prevStateRoot[:]).Hex(), lastCall.HeadBlockHash)
	require.Equal(t, common.BytesToHash(prevStateRoot[:]).Hex(), lastCall.SafeBlockHash)
	require.Equal(t, common.BytesToHash(prevStateRoot[:]).Hex(), lastCall.FinalizedBlockHash)

	mockStateRoot := common.HexToHash("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	var expectedStateRoot execution_types.Hash
	copy(expectedStateRoot[:], mockStateRoot.Bytes())

	require.Equal(t, expectedStateRoot, stateRoot)
	require.Equal(t, uint64(21000), gasUsed)
}

func TestEngineAPIExecutionClient_GetTxs(t *testing.T) {
	mockEngine := mocks.NewMockEngineAPI(t)
	defer mockEngine.Close()

	mockEth := mocks.NewMockEthAPI(t)
	defer mockEth.Close()

	jwtSecret := generateTestJWTSecret()
	client, err := NewEngineAPIExecutionClient(
		&proxy_json_rpc.Config{},
		mockEth.URL,
		mockEngine.URL,
		jwtSecret,
		common.Hash{},
		common.Address{},
	)
	require.NoError(t, err)

	mockEth.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var resp interface{}

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var req map[string]interface{}
		err = json.Unmarshal(body, &req)
		require.NoError(t, err)

		method := req["method"].(string)
		if method == "txpool_content" {
			resp = map[string]interface{}{
				"pending": map[string]interface{}{
					"0x1234567890123456789012345678901234567890": map[string]interface{}{
						"0": map[string]interface{}{
							"input":    "0x123456",
							"nonce":    "0x0",
							"from":     "0x1234567890123456789012345678901234567890",
							"to":       "0x0987654321098765432109876543210987654321",
							"value":    "0x0",
							"gas":      "0x5208",
							"gasPrice": "0x3b9aca00",
							"chainId":  "0x1",
							"v":        "0x1b",
							"r":        "0x1234",
							"s":        "0x5678",
							"hash":     "0x1234567890123456789012345678901234567890123456789012345678901234",
							"type":     "0x0",
						},
					},
				},
				"queued": map[string]interface{}{},
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"result":  resp,
		})
	}))

	ctx := context.Background()
	txs, err := client.GetTxs(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, txs)
	require.Greater(t, len(txs), 0)
}

func TestEngineAPIExecutionClient_SetFinal(t *testing.T) {
	mockEngine := mocks.NewMockEngineAPI(t)
	defer mockEngine.Close()

	mockEth := mocks.NewMockEthAPI(t)
	defer mockEth.Close()

	jwtSecret := generateTestJWTSecret()
	client, err := NewEngineAPIExecutionClient(
		&proxy_json_rpc.Config{},
		mockEth.URL,
		mockEngine.URL,
		jwtSecret,
		common.Hash{},
		common.Address{},
	)
	require.NoError(t, err)

	blockHeight := uint64(1)
	ctx := context.Background()
	err = client.SetFinal(ctx, blockHeight)
	require.NoError(t, err)

	lastCall := mockEngine.GetLastForkchoiceUpdated()
	require.NotNil(t, lastCall)

	expectedBlockHash := "0x4bbb1357b89ddc1b1371f9ae83b72739a1815628f8648665fc332c3f0fb8d853"
	require.Equal(t, expectedBlockHash, lastCall.FinalizedBlockHash)
	require.Equal(t, expectedBlockHash, lastCall.HeadBlockHash)
	require.Equal(t, expectedBlockHash, lastCall.SafeBlockHash)
}
