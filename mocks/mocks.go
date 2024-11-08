package mocks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type MockEngineAPI struct {
	*httptest.Server
}

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
				"gasUsed":   float64(21000),
				"gasLimit":  float64(1000000),
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
					"sha3Uncles":       "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
					"logsBloom":        "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
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
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      req["id"],
			"result":  resp,
		})
	}))

	return mock
}
