package integration_tests

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rollkit/go-execution-evm"
	"github.com/stretchr/testify/require"

	proxy_json_rpc "github.com/rollkit/go-execution/proxy/jsonrpc"
	rollkit_types "github.com/rollkit/go-execution/types"
)

const (
	TEST_ETH_URL    = "http://localhost:8545"
	TEST_ENGINE_URL = "http://localhost:8551"

	CHAIN_ID = "1234"
	GENESIS_HASH = "0x8bf225d50da44f60dee1c4ee6f810fe5b44723c76ac765654b6692d50459f216"
	// TODO: programatically spin up docker and share secrets
	JWT_SECRET = "09a23c010d96caaebb21c193b85d30bbb62a9bac5bd0a684e9e91c77c811ca65" 
)

func TestEngineAPIExecutionClient_InitChain(t *testing.T) {
	genesisHash := common.HexToHash(GENESIS_HASH)
	client, err := execution.NewEngineAPIExecutionClient(
		&proxy_json_rpc.Config{},
		TEST_ETH_URL,
		TEST_ENGINE_URL,
		JWT_SECRET,
		genesisHash,
		common.Address{},
	)
	require.NoError(t, err)

	genesisTime := time.Now().UTC().Truncate(time.Second)
	initialHeight := uint64(0)

	stateRoot, gasLimit, err := client.InitChain(genesisTime, initialHeight, CHAIN_ID)
	require.NoError(t, err)

	mockStateRoot := common.HexToHash("0x362b7d8a31e7671b0f357756221ac385790c25a27ab222dc8cbdd08944f5aea4")
	var expectedStateRoot rollkit_types.Hash
	copy(expectedStateRoot[:], mockStateRoot.Bytes())

	require.Equal(t, expectedStateRoot, stateRoot)
	require.Equal(t, uint64(1000000), gasLimit)
}
