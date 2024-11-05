package execution

import (
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rollkit/go-execution-evm/proxy"
	"github.com/rollkit/go-execution/mocks"
	proxy_json_rpc "github.com/rollkit/go-execution/proxy/jsonrpc"
	rollkit_types "github.com/rollkit/rollkit/types"
	"github.com/stretchr/testify/require"
)

const (
	jwtSecretFile = "jwt.hex"
)

type testEnv struct {
	server    *httptest.Server
	jwtSecret string
	cleanup   func()
	client    *EngineAPIExecutionClient
	proxyConf *proxy_json_rpc.Config
	mockExec  *mocks.MockExecute
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "execution-test-*")
	require.NoError(t, err)

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	// setup a proxy config
	proxyConf := &proxy_json_rpc.Config{
		DefaultTimeout: 5 * time.Second,
		MaxRequestSize: 1024 * 1024,
	}

	// create a mock execute from mocks package
	mockExec := mocks.NewMockExecute(t)

	// create a proxy server with mock execute
	server := proxy_json_rpc.NewServer(mockExec, proxyConf)
	testServer := httptest.NewServer(server)

	// create a proxy client that implements the Execute interface
	ethURL := "http://localhost:8545"
	engineURL := "http://localhost:8551"
	genesisHash := common.HexToHash("0x0")
	feeRecipient := common.HexToAddress("0x0")

	proxyClient, err := proxy.NewClient(proxyConf, ethURL, engineURL, genesisHash, feeRecipient)
	require.NoError(t, err)

	err = proxyClient.Start(testServer.URL)
	require.NoError(t, err)

	// create an execution client with the proxy client
	client, err := NewEngineAPIExecutionClient(proxyClient)
	require.NoError(t, err)

	return &testEnv{
		server:    testServer,
		jwtSecret: "",
		cleanup: func() {
			cleanup()
			testServer.Close()
			proxyClient.Stop()
		},
		client:    client,
		proxyConf: proxyConf,
		mockExec:  mockExec,
	}
}

func TestEngineAPIExecutionClient_InitChain(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	genesisTime := time.Now().UTC().Truncate(time.Second)
	initialHeight := uint64(0)
	chainID := "11155111" // sepolia chain id

	expectedStateRoot := rollkit_types.Hash{}
	copy(expectedStateRoot[:], []byte{1, 2, 3})
	expectedGasLimit := uint64(1000000)

	env.mockExec.On("InitChain", genesisTime, initialHeight, chainID).
		Return(expectedStateRoot, expectedGasLimit, nil)

	stateRoot, gasLimit, err := env.client.InitChain(genesisTime, initialHeight, chainID)
	require.NoError(t, err)
	require.Equal(t, expectedStateRoot, stateRoot)
	require.Equal(t, expectedGasLimit, gasLimit)

	env.mockExec.AssertExpectations(t)
}

func TestEngineAPIExecutionClient_GetTxs(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	expectedTxs := []rollkit_types.Tx{[]byte("tx1"), []byte("tx2")}
	env.mockExec.On("GetTxs").Return(expectedTxs, nil)

	txs, err := env.client.GetTxs()
	require.NoError(t, err)
	require.Equal(t, expectedTxs, txs)

	env.mockExec.AssertExpectations(t)
}

func TestEngineAPIExecutionClient_ExecuteTxs(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	blockHeight := uint64(1)
	timestamp := time.Now().UTC().Truncate(time.Second)
	prevStateRoot := rollkit_types.Hash{}
	copy(prevStateRoot[:], []byte{1, 2, 3})
	testTx := rollkit_types.Tx("test transaction")

	expectedStateRoot := rollkit_types.Hash{}
	copy(expectedStateRoot[:], []byte{4, 5, 6})
	expectedGasUsed := uint64(21000)

	env.mockExec.On("ExecuteTxs", []rollkit_types.Tx{testTx}, blockHeight, timestamp, prevStateRoot).
		Return(expectedStateRoot, expectedGasUsed, nil)

	stateRoot, gasUsed, err := env.client.ExecuteTxs(
		[]rollkit_types.Tx{testTx},
		blockHeight,
		timestamp,
		prevStateRoot,
	)
	require.NoError(t, err)
	require.Equal(t, expectedStateRoot, stateRoot)
	require.Equal(t, expectedGasUsed, gasUsed)

	env.mockExec.AssertExpectations(t)
}

func TestEngineAPIExecutionClient_SetFinal(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	blockHeight := uint64(1)

	env.mockExec.On("SetFinal", blockHeight).Return(nil)

	err := env.client.SetFinal(blockHeight)
	require.NoError(t, err)

	env.mockExec.AssertExpectations(t)
}
