package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rollkit/go-execution-evm/mocks"
	proxy_json_rpc "github.com/rollkit/go-execution/proxy/jsonrpc"
	execution_types "github.com/rollkit/go-execution/types"
	"github.com/stretchr/testify/require"
)
type mockEngineAPI struct {
	*httptest.Server
}

func newMockEngineAPI(t *testing.T) *mockEngineAPI {
	t.Helper()

	mock := &mockEngineAPI{}
	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var resp map[string]interface{}

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var req map[string]interface{}
		err = json.Unmarshal(body, &req)
		require.NoError(t, err)

		method := req["method"].(string)
		switch method {
		case "engine_newPayloadV1":
			resp = map[string]interface{}{
				"status":          "VALID",
				"latestValidHash": "0x1234",
			}
		case "engine_forkchoiceUpdatedV1":
			resp = map[string]interface{}{
				"payloadStatus": map[string]interface{}{
					"status": "VALID",
				},
				"payloadId": "0x1234",
			}
		case "engine_getPayloadV1":
			resp = map[string]interface{}{
				"stateRoot": "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"gasUsed":   "0x5208",
				"gasLimit":  "0xf4240",
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"result":  resp,
		})
	}))

	return mock
}

type mockEthAPI struct {
	*httptest.Server
}

func newMockEthAPI(t *testing.T) *mockEthAPI {
	t.Helper()

	mock := &mockEthAPI{}
	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var resp interface{}

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var req map[string]interface{}
		err = json.Unmarshal(body, &req)
		require.NoError(t, err)

		method := req["method"].(string)
		switch method {
		case "txpool_content":
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
		case "eth_getBlockByNumber", "eth_blockByNumber":
			params := req["params"].([]interface{})
			blockNumRaw := params[0]
			fullTx := false
			if len(params) > 1 {
				fullTx = params[1].(bool)
			}

			var blockNum string
			switch v := blockNumRaw.(type) {
			case string:
				blockNum = v
			case float64:
				blockNum = fmt.Sprintf("0x%x", int64(v))
			}

			if blockNum == "0x1" {
				emptyBlockHash := "0x0000000000000000000000000000000000000000000000000000000000000000"
				blockResp := map[string]interface{}{
					"hash":             "0x1234567890123456789012345678901234567890123456789012345678901234",
					"number":           "0x1",
					"parentHash":       emptyBlockHash,
					"timestamp":        "0x0",
					"stateRoot":        "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"receiptsRoot":     emptyBlockHash,
					"transactionsRoot": emptyBlockHash,
					"sha3Uncles":       emptyBlockHash,
					"logsBloom":        "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					"difficulty":       "0x0",
					"totalDifficulty":  "0x0",
					"size":             "0x0",
					"gasLimit":         "0x1000000",
					"gasUsed":          "0x0",
					"miner":            "0x0000000000000000000000000000000000000000",
					"extraData":        "0x",
					"mixHash":          emptyBlockHash,
					"nonce":            "0x0000000000000000",
					"baseFeePerGas":    "0x0",
					"uncles":           []interface{}{},
				}

				if fullTx {
					blockResp["transactions"] = []interface{}{}
				} else {
					blockResp["transactions"] = []interface{}{}
				}

				resp = blockResp
			}
			t.Logf("Requested block number: %s, Matching: %v", blockNum, blockNum == "0x1")
		}

		t.Logf("Request: %s, Params: %v", method, req["params"])
		t.Logf("Response: %v", resp)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"result":  resp,
		})
	}))

	return mock
}

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
	var expectedStateRoot execution_types.Hash
	copy(expectedStateRoot[:], mockStateRoot.Bytes())

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

	var prevStateRoot execution_types.Hash
	copy(prevStateRoot[:], []byte{1, 2, 3})

	testTx := execution_types.Tx("test transaction")

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
