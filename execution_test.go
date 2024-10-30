package execution

import (
	"context"
	"math/big"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/rollkit/go-execution/proxy/jsonrpc"
	rollkitTypes "github.com/rollkit/rollkit/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	jwtSecretFile = "jwt.hex"
)

type testEnv struct {
	server    *httptest.Server
	jwtSecret string
	ethURL    string
	engineURL string
	cleanup   func()
	client    *EngineAPIExecutionClient
	proxyConf *jsonrpc.Config
	mockExec  *MockExecutor
}

// Add MockExecutor
type MockExecutor struct {
	mock.Mock
}

func NewMockExecutor() *MockExecutor {
	return &MockExecutor{}
}

func (m *MockExecutor) InitChain(genesisTime time.Time, initialHeight uint64, chainID string) (rollkitTypes.Hash, uint64, error) {
	args := m.Called(genesisTime, initialHeight, chainID)
	return args.Get(0).(rollkitTypes.Hash), args.Get(1).(uint64), args.Error(2)
}

func (m *MockExecutor) GetTxs() ([]rollkitTypes.Tx, error) {
	args := m.Called()
	return args.Get(0).([]rollkitTypes.Tx), args.Error(1)
}

func (m *MockExecutor) ExecuteTxs(txs []rollkitTypes.Tx, height uint64, timestamp time.Time, prevStateRoot rollkitTypes.Hash) (rollkitTypes.Hash, uint64, error) {
	args := m.Called(txs, height, timestamp, prevStateRoot)
	return args.Get(0).(rollkitTypes.Hash), args.Get(1).(uint64), args.Error(2)
}

func (m *MockExecutor) SetFinal(height uint64) error {
	args := m.Called(height)
	return args.Error(0)
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	// Create temporary directory for JWT token
	tmpDir, err := os.MkdirTemp("", "execution-test-*")
	require.NoError(t, err)

	// Setup cleanup
	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	// Setup proxy config
	proxyConf := &jsonrpc.Config{
		DefaultTimeout: 5 * time.Second,
		MaxRequestSize: 1024 * 1024,
	}

	// Create mock executor
	mockExec := NewMockExecutor()

	// Create proxy server with mock executor
	server := jsonrpc.NewServer(mockExec, proxyConf)
	testServer := httptest.NewServer(server)

	// Create proxy client
	proxyClient := jsonrpc.NewClient()
	proxyClient.SetConfig(proxyConf)

	err = proxyClient.Start(testServer.URL)
	require.NoError(t, err)

	// Create execution client with proxy client
	ethURL := "http://localhost:8545"
	genesisHash := common.HexToHash("0x0")
	feeRecipient := common.HexToAddress("0x0")

	client, err := NewEngineAPIExecutionClient(
		ethURL,
		proxyClient, // Pass the proxy client
		genesisHash,
		feeRecipient,
	)
	require.NoError(t, err)

	return &testEnv{
		server:    testServer,
		jwtSecret: "", // Not needed for test server
		ethURL:    ethURL,
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
	chainID := "11155111" // Sepolia chain ID

	// Setup mock expectations using env.mockExec
	expectedStateRoot := rollkitTypes.Hash{}
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

	txs, err := env.client.GetTxs()
	require.NoError(t, err)
	// Initially pool should be empty
	require.Empty(t, txs)

	// TO-DO: Add test transaction to pool and verify it's retrieved
}

func TestEngineAPIExecutionClient_ExecuteTxs(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	// Setup test data
	blockHeight := uint64(1)
	timestamp := time.Now()

	// Get the previous state root from the client
	header, err := env.client.ethClient.HeaderByNumber(context.Background(), big.NewInt(0))
	require.NoError(t, err)

	// Convert the header root to the expected type
	headerHash := rollkitTypes.Hash(header.Root[:]) // Convert to rollkit Hash type

	// Create test transaction
	testTx := []byte{} // Add test transaction bytes

	stateRoot, gasUsed, err := env.client.ExecuteTxs(
		[]rollkitTypes.Tx{testTx},
		blockHeight,
		timestamp,
		headerHash,
	)
	require.NoError(t, err)
	require.NotEqual(t, common.Hash{}, stateRoot)
	require.Greater(t, gasUsed, uint64(0))
}

func TestEngineAPIExecutionClient_SetFinal(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	// First create a block
	blockHeight := uint64(1)
	err := env.client.SetFinal(blockHeight)
	require.NoError(t, err)
}
