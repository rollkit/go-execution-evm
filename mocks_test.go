package execution_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type MockEngineAPI struct {
	*httptest.Server
}

type forkChoiceState struct {
	HeadBlockHash      string
	SafeBlockHash      string
	FinalizedBlockHash string
}

var lastForkchoiceUpdate *forkChoiceState

func NewMockEngineAPI(t *testing.T) *MockEngineAPI {
	t.Helper()

	mock := &MockEngineAPI{}
	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var resp map[string]interface{}

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var req map[string]interface{}
		err = json.Unmarshal(body, &req)
		require.NoError(t, err)

		method := req["method"].(string)
		switch method {
		case "engine_newPayloadV3":
			resp = map[string]interface{}{
				"status":          "VALID",
				"latestValidHash": "0x222211113333444455556666777788889999aaaabbbbccccddddeeeeffff0000",
				"validationError": nil,
			}
		case "engine_forkchoiceUpdatedV3":
			params := req["params"].([]interface{})
			forkchoiceState := params[0].(map[string]interface{})

			lastForkchoiceUpdate = &forkChoiceState{
				HeadBlockHash:      forkchoiceState["headBlockHash"].(string),
				SafeBlockHash:      forkchoiceState["safeBlockHash"].(string),
				FinalizedBlockHash: forkchoiceState["finalizedBlockHash"].(string),
			}

			resp = map[string]interface{}{
				"payloadStatus": map[string]interface{}{
					"status":          "VALID",
					"latestValidHash": nil,
					"validationError": nil,
				},
				"payloadId": "0x123456789abcdef0",
			}
		case "engine_getPayloadV3":
			resp = map[string]interface{}{
				"executionPayload": map[string]interface{}{
					"parentHash":    "0x0000000000000000000000000000000000000000000000000000000000000000",
					"feeRecipient":  "0x0000000000000000000000000000000000000000",
					"stateRoot":     "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"receiptsRoot":  "0x0000000000000000000000000000000000000000000000000000000000000000",
					"logsBloom":     "0x00000000000000000000000000000000",
					"prevRandao":    "0x0000000000000000000000000000000000000000000000000000000000000000",
					"blockNumber":   "0x0",
					"gasLimit":      "0xf4240",
					"gasUsed":       "0x5208",
					"timestamp":     "0x0",
					"extraData":     "0x",
					"baseFeePerGas": "0x0",
					"blockHash":     "0x0000000000000000000000000000000000000000000000000000000000000000",
					"transactions":  []string{},
				},
				"blockValue": "0x0",
				"blobsBundle": map[string]interface{}{
					"commitments": []string{},
					"proofs":      []string{},
					"blobs":       []string{},
				},
				"shouldOverrideBuilder": false,
			}
		}

		err = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"result":  resp,
		})
		require.NoError(t, err)
	}))

	return mock
}

type MockEthAPI struct {
	*httptest.Server
}

func NewMockEthAPI(t *testing.T) *MockEthAPI {
	t.Helper()

	mock := &MockEthAPI{}
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

			var blockNum string
			switch v := blockNumRaw.(type) {
			case string:
				blockNum = v
			case float64:
				blockNum = fmt.Sprintf("0x%x", int64(v))
			}

			if blockNum == "0x1" {
				emptyTrieRoot := "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
				emptyBlockHash := "0x0000000000000000000000000000000000000000000000000000000000000000"
				emptyBloom := "0x" + strings.Repeat("0", 512)
				blockHash := "0x4bbb1357b89ddc1b1371f9ae83b72739a1815628f8648665fc332c3f0fb8d853"

				blockResp := map[string]interface{}{
					"hash":             blockHash,
					"number":           "0x1",
					"parentHash":       emptyBlockHash,
					"timestamp":        "0x0",
					"stateRoot":        "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
					"receiptsRoot":     emptyTrieRoot,
					"transactionsRoot": emptyTrieRoot,
					"sha3Uncles":       "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
					"logsBloom":        emptyBloom,
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
					"transactions":     []interface{}{},
				}

				resp = blockResp
			}
		}

		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"], "result": resp,
		})
	}))

	return mock
}

func (m *MockEngineAPI) GetLastForkchoiceUpdated() *forkChoiceState {
	return lastForkchoiceUpdate
}
