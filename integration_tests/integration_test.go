package integration_tests

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rollkit/go-execution-evm"
	"github.com/stretchr/testify/require"

	proxy_json_rpc "github.com/rollkit/go-execution/proxy/jsonrpc"
)

const (
	TEST_ETH_URL    = "http://localhost:8545"
	TEST_ENGINE_URL = "http://localhost:8551"

	CHAIN_ID = "1234"
	GENESIS_HASH = "0x8bf225d50da44f60dee1c4ee6f810fe5b44723c76ac765654b6692d50459f216"
)

func TestEngineAPIExecutionClient_InitChain(t *testing.T) {
	genesisHash := common.HexToHash(GENESIS_HASH)
	client, err := execution.NewEngineAPIExecutionClient(
		&proxy_json_rpc.Config{},
		TEST_ETH_URL,
		TEST_ENGINE_URL,
		genesisHash,
		common.Address{},
	)
	require.NoError(t, err)

	genesisTime := time.Now().UTC().Truncate(time.Second)
	initialHeight := uint64(0)

	_, _, err = client.InitChain(genesisTime, initialHeight, CHAIN_ID)
	require.NoError(t, err)
}
