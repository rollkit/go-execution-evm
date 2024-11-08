package execution

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rollkit/go-execution-evm/mocks"
	proxy_json_rpc "github.com/rollkit/go-execution/proxy/jsonrpc"
	execution_types "github.com/rollkit/go-execution/types"
	"github.com/stretchr/testify/require"
)

func TestEngineAPIExecutionClient_InitChain(t *testing.T) {
	mockEngine := mocks.NewMockEngineAPI(t)
	defer mockEngine.Close()

	mockEth := mocks.NewMockEthAPI(t)
	defer mockEth.Close()

	client, err := NewEngineAPIExecutionClient(
		&proxy_json_rpc.Config{},
		mockEth.URL,
		mockEngine.URL,
		common.Hash{},
		common.Address{},
	)
	require.NoError(t, err)

	genesisTime := time.Now().UTC().Truncate(time.Second)
	initialHeight := uint64(0)
	chainID := "11155111" // sepolia chain id

	stateRoot, gasLimit, err := client.InitChain(genesisTime, initialHeight, chainID)
	require.NoError(t, err)

	mockStateRoot := common.HexToHash("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	var expectedStateRoot execution_types.Hash
	copy(expectedStateRoot[:], mockStateRoot.Bytes())

	require.Equal(t, expectedStateRoot, stateRoot)
	require.Equal(t, uint64(1000000), gasLimit)
}

func TestEngineAPIExecutionClient_GetTxs(t *testing.T) {
	mockEngine := mocks.NewMockEngineAPI(t)
	defer mockEngine.Close()

	mockEth := mocks.NewMockEthAPI(t)
	defer mockEth.Close()

	client, err := NewEngineAPIExecutionClient(
		&proxy_json_rpc.Config{},
		mockEth.URL,
		mockEngine.URL,
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

	txs, err := client.GetTxs()
	require.NoError(t, err)
	require.NotEmpty(t, txs)
	require.Greater(t, len(txs), 0)
}

func TestEngineAPIExecutionClient_ExecuteTxs(t *testing.T) {
	mockEngine := mocks.NewMockEngineAPI(t)
	defer mockEngine.Close()

	mockEth := mocks.NewMockEthAPI(t)
	defer mockEth.Close()

	client, err := NewEngineAPIExecutionClient(
		&proxy_json_rpc.Config{},
		mockEth.URL,
		mockEngine.URL,
		common.Hash{},
		common.Address{},
	)
	require.NoError(t, err)

	blockHeight := uint64(1)
	timestamp := time.Now().UTC().Truncate(time.Second)

	var prevStateRoot execution_types.Hash
	copy(prevStateRoot[:], []byte{1, 2, 3})

	testTx := execution_types.Tx("test transaction")

	stateRoot, gasUsed, err := client.ExecuteTxs(
		[]execution_types.Tx{testTx},
		blockHeight,
		timestamp,
		prevStateRoot,
	)
	require.NoError(t, err)

	mockStateRoot := common.HexToHash("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	var expectedStateRoot execution_types.Hash
	copy(expectedStateRoot[:], mockStateRoot.Bytes())

	require.Equal(t, expectedStateRoot, stateRoot)
	require.Equal(t, uint64(21000), gasUsed)
}

func TestEngineAPIExecutionClient_SetFinal(t *testing.T) {
	mockEngine := mocks.NewMockEngineAPI(t)
	defer mockEngine.Close()

	mockEth := mocks.NewMockEthAPI(t)
	defer mockEth.Close()

	client, err := NewEngineAPIExecutionClient(
		&proxy_json_rpc.Config{},
		mockEth.URL,
		mockEngine.URL,
		common.Hash{},
		common.Address{},
	)
	require.NoError(t, err)

	blockHeight := uint64(1)
	err = client.SetFinal(blockHeight)
	require.NoError(t, err)

	lastCall := mockEngine.GetLastForkchoiceUpdated()
	require.NotNil(t, lastCall)

	expectedBlockHash := "0x4bbb1357b89ddc1b1371f9ae83b72739a1815628f8648665fc332c3f0fb8d853"
	require.Equal(t, expectedBlockHash, lastCall.FinalizedBlockHash)
}
