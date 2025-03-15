package execution

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

const (
	TEST_ETH_URL    = "http://localhost:8545"
	TEST_ENGINE_URL = "http://localhost:8551"

	CHAIN_ID          = "1234"
	GENESIS_HASH      = "0x568201e3a763b59f7c646d72bf75a25aafff57f98a82dbd7b50542382c55f372"
	GENESIS_STATEROOT = "0x362b7d8a31e7671b0f357756221ac385790c25a27ab222dc8cbdd08944f5aea4"
	TEST_PRIVATE_KEY  = "cece4f25ac74deb1468965160c7185e07dff413f23fcadb611b05ca37ab0a52e"
	TEST_TO_ADDRESS   = "0x944fDcD1c868E3cC566C78023CcB38A32cDA836E"

	DOCKER_PATH  = "./docker"
	JWT_FILENAME = "testsecret.hex"
)

// TestEngineExecution tests the end-to-end execution flow of the EVM engine client.
// The test has two phases:
//
// Build Chain Phase:
// - Sets up test Reth engine with JWT auth
// - Initializes chain with genesis parameters
// - For blocks 1-10:
//   - Generates and submits random transactions
//   - Block 4 has 0 transactions as edge case
//   - Executes transactions and verifies state changes
//   - Stores payloads for sync testing
//
// Sync Chain Phase:
// - Creates fresh engine instance
// - Replays stored payloads
// - Verifies execution matches original:
//   - State roots
//   - Block data
//   - Transaction counts
//
// Validates the engine can process transactions, maintain state,
// handle empty blocks, and support chain replication.
func TestEngineExecution(t *testing.T) {
	allPayloads := make([][][]byte, 0) // Slice to store payloads from build to sync phase

	initialHeight := uint64(0)
	genesisHash := common.HexToHash(GENESIS_HASH)
	genesisTime := time.Now().UTC().Truncate(time.Second)
	genesisStateRoot := common.HexToHash(GENESIS_STATEROOT)
	rollkitGenesisStateRoot := genesisStateRoot[:]

	t.Run("Build chain", func(tt *testing.T) {
		jwtSecret := setupTestRethEngine(tt)

		executionClient, err := NewPureEngineExecutionClient(
			TEST_ETH_URL,
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

		prevStateRoot := rollkitGenesisStateRoot
		lastHeight, lastHash, lastTxs := checkLatestBlock(tt, ctx)

		for blockHeight := initialHeight + 1; blockHeight <= 10; blockHeight++ {
			nTxs := int(blockHeight) + 10
			// randomly use no transactions
			if blockHeight == 4 {
				nTxs = 0
			}
			txs := make([]*ethTypes.Transaction, nTxs)
			for i := range txs {
				txs[i] = getRandomTransaction(t, 22000)
			}
			for i := range txs {
				submitTransaction(t, txs[i])
			}
			time.Sleep(1000 * time.Millisecond)

			payload, err := executionClient.GetTxs(ctx)
			require.NoError(tt, err)
			require.Len(tt, payload, nTxs+1)

			allPayloads = append(allPayloads, payload)

			// Check latest block before execution
			beforeHeight, beforeHash, beforeTxs := checkLatestBlock(tt, ctx)
			require.Equal(tt, lastHeight, beforeHeight, "Latest block height should match")
			require.Equal(tt, lastHash.Hex(), beforeHash.Hex(), "Latest block hash should match")
			require.Equal(tt, lastTxs, beforeTxs, "Number of transactions should match")

			newStateRoot, maxBytes, err := executionClient.ExecuteTxs(ctx, payload, blockHeight, genesisTime, prevStateRoot)
			require.NoError(tt, err)
			require.NotZero(tt, maxBytes)

			err = executionClient.SetFinal(ctx, blockHeight)
			require.NoError(tt, err)

			// Check latest block after execution
			lastHeight, lastHash, lastTxs = checkLatestBlock(tt, ctx)
			require.Equal(tt, blockHeight, lastHeight, "Latest block height should match")
			require.NotEmpty(tt, lastHash.Hex(), "Latest block hash should not be empty")
			require.GreaterOrEqual(tt, lastTxs, 0, "Number of transactions should be non-negative")

			if nTxs == 0 {
				require.Equal(tt, prevStateRoot, newStateRoot)
			} else {
				require.NotEqual(tt, prevStateRoot, newStateRoot)
			}
			prevStateRoot = newStateRoot
		}
	})

	// start new container and try to sync
	t.Run("Sync chain", func(tt *testing.T) {
		jwtSecret := setupTestRethEngine(t)

		executionClient, err := NewPureEngineExecutionClient(
			TEST_ETH_URL,
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

		prevStateRoot := rollkitGenesisStateRoot
		lastHeight, lastHash, lastTxs := checkLatestBlock(tt, ctx)

		for blockHeight := initialHeight + 1; blockHeight-initialHeight <= 10; blockHeight++ {
			payload := allPayloads[blockHeight-initialHeight-1]

			// Check latest block before execution
			beforeHeight, beforeHash, beforeTxs := checkLatestBlock(tt, ctx)
			require.Equal(tt, lastHeight, beforeHeight, "Latest block height should match")
			require.Equal(tt, lastHash.Hex(), beforeHash.Hex(), "Latest block hash should match")
			require.Equal(tt, lastTxs, beforeTxs, "Number of transactions should match")

			newStateRoot, maxBytes, err := executionClient.ExecuteTxs(ctx, payload, blockHeight, genesisTime, prevStateRoot)
			require.NoErrorf(tt, err, "blockHeight: %d, nTxs: %d", blockHeight, len(payload)-1)
			require.NotZero(tt, maxBytes)

			err = executionClient.SetFinal(ctx, blockHeight)
			require.NoError(tt, err)

			// Check latest block after execution
			lastHeight, lastHash, lastTxs = checkLatestBlock(tt, ctx)
			require.Equal(tt, blockHeight, lastHeight, "Latest block height should match")
			require.NotEmpty(tt, lastHash.Hex(), "Latest block hash should not be empty")
			require.GreaterOrEqual(tt, lastTxs, 0, "Number of transactions should be non-negative")

			if len(payload)-1 == 0 {
				require.Equal(tt, prevStateRoot, newStateRoot)
			} else {
				require.NotEqual(tt, prevStateRoot, newStateRoot)
			}
			prevStateRoot = newStateRoot
		}
	})
}

// createEthClient creates an Ethereum client for checking block information
func createEthClient(t *testing.T) *ethclient.Client {
	t.Helper()

	// Use the same ETH URL as in the tests
	ethClient, err := ethclient.Dial(TEST_ETH_URL)
	require.NoError(t, err, "Failed to create Ethereum client")

	return ethClient
}

// checkLatestBlock retrieves and returns the latest block height, hash, and transaction count using Ethereum API
func checkLatestBlock(t *testing.T, ctx context.Context) (uint64, common.Hash, int) {
	t.Helper()

	// Create an Ethereum client
	ethClient := createEthClient(t)
	defer ethClient.Close()

	// Get the latest block header
	header, err := ethClient.HeaderByNumber(ctx, nil) // nil means latest block
	if err != nil {
		t.Logf("Warning: Failed to get latest block header: %v", err)
		return 0, common.Hash{}, 0
	}

	blockNumber := header.Number.Uint64()
	blockHash := header.Hash()

	// Get the full block to count transactions
	block, err := ethClient.BlockByNumber(ctx, header.Number)
	if err != nil {
		t.Logf("Warning: Failed to get full block: %v", err)
		t.Logf("Latest block: height=%d, hash=%s, txs=unknown", blockNumber, blockHash.Hex())
		return blockNumber, blockHash, 0
	}

	txCount := len(block.Transactions())

	//t.Logf("Latest block: height=%d, hash=%s, txs=%d", blockNumber, blockHash.Hex(), txCount)
	return blockNumber, blockHash, txCount
}

// generateJWTSecret generates a random JWT secret
func generateJWTSecret() (string, error) {
	jwtSecret := make([]byte, 32)
	_, err := rand.Read(jwtSecret)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return hex.EncodeToString(jwtSecret), nil
}

// setupTestRethEngine starts a reth container and returns the JWT secret
func setupTestRethEngine(t *testing.T) string {
	t.Helper()

	chainPath, err := filepath.Abs(filepath.Join(DOCKER_PATH, "chain"))
	require.NoError(t, err)

	jwtPath, err := filepath.Abs(filepath.Join(DOCKER_PATH, "jwttoken"))
	require.NoError(t, err)

	err = os.MkdirAll(jwtPath, 0750)
	require.NoError(t, err)

	jwtSecret, err := generateJWTSecret()
	require.NoError(t, err)

	jwtFile := filepath.Join(jwtPath, JWT_FILENAME)
	err = os.WriteFile(jwtFile, []byte(jwtSecret), 0600)
	require.NoError(t, err)

	t.Cleanup(func() {
		err := os.Remove(jwtFile)
		require.NoError(t, err)
	})

	rethReq := testcontainers.ContainerRequest{
		Name:       "reth",
		Image:      "ghcr.io/paradigmxyz/reth:v1.2.1",
		Entrypoint: []string{"/bin/sh", "-c"},
		Cmd: []string{
			`
				reth node \
          		--chain /root/chain/genesis.json \
          		--metrics 0.0.0.0:9001 \
          		--log.file.directory /root/logs \
          		--authrpc.addr 0.0.0.0 \
          		--authrpc.port 8551 \
          		--authrpc.jwtsecret /root/jwt/testsecret.hex \
          		--http --http.addr 0.0.0.0 --http.port 8545 \
          		--http.api "eth,net,web3,txpool" \
          		--disable-discovery \
				-vvvv
				`,
		},
		ExposedPorts: []string{"8545/tcp", "8551/tcp"},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Binds = []string{
				chainPath + ":/root/chain:ro",
				jwtPath + ":/root/jwt:ro",
			}
			hc.PortBindings = nat.PortMap{
				"8545/tcp": []nat.PortBinding{
					{
						HostIP:   "0.0.0.0",
						HostPort: "8545",
					},
				},
				"8551/tcp": []nat.PortBinding{
					{
						HostIP:   "0.0.0.0",
						HostPort: "8551",
					},
				},
			}
		},
	}
	ctx := context.Background()
	rethContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: rethReq,
		Started:          true,
	})
	require.NoError(t, err)

	testcontainers.CleanupContainer(t, rethContainer)

	err = waitForRethContainer(t, jwtSecret)
	require.NoError(t, err)

	return jwtSecret
}

// waitForRethContainer polls the reth endpoints until they're ready or timeout occurs
func waitForRethContainer(t *testing.T, jwtSecret string) error {
	t.Helper()

	client := &http.Client{
		Timeout: 100 * time.Millisecond,
	}

	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			// Try to get container logs before returning timeout error
			cli, err := testcontainers.NewDockerClientWithOpts(context.Background())
			if err == nil {
				reader, err := cli.ContainerLogs(context.Background(), "reth", container.LogsOptions{
					ShowStdout: true,
					ShowStderr: true,
					Follow:     false,
				})
				if err == nil {
					defer func() {
						if err := reader.Close(); err != nil {
							t.Logf("Error closing container logs reader: %v", err)
						}
					}()
					logs, err := io.ReadAll(reader)
					if err == nil {
						t.Logf("Container logs:\n%s", string(logs))
					}
				}
			}
			return fmt.Errorf("timeout waiting for reth container to be ready")
		default:
			// check :8545 is ready
			rpcReq := strings.NewReader(`{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}`)
			resp, err := client.Post(TEST_ETH_URL, "application/json", rpcReq)
			if err == nil {
				if err := resp.Body.Close(); err != nil {
					return fmt.Errorf("failed to close response body: %w", err)
				}
				if resp.StatusCode == http.StatusOK {
					// check :8551 is ready with a stateless call
					req, err := http.NewRequest("POST", TEST_ENGINE_URL, strings.NewReader(`{"jsonrpc":"2.0","method":"engine_getClientVersionV1","params":[],"id":1}`))
					if err != nil {
						return err
					}
					req.Header.Set("Content-Type", "application/json")

					secret, err := decodeSecret(jwtSecret)
					if err != nil {
						return err
					}

					authToken, err := getAuthToken(secret)
					if err != nil {
						return err
					}

					req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))

					resp, err := client.Do(req)
					if err == nil {
						if err := resp.Body.Close(); err != nil {
							return fmt.Errorf("failed to close response body: %w", err)
						}
						if resp.StatusCode == http.StatusOK {
							return nil
						}
					}
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// submitTransaction submits a signed transaction to the Ethereum client
func submitTransaction(t *testing.T, signedTx *ethTypes.Transaction) {
	rpcClient, err := ethclient.Dial(TEST_ETH_URL)
	require.NoError(t, err)
	err = rpcClient.SendTransaction(context.Background(), signedTx)
	require.NoError(t, err)
}

var lastNonce uint64

// getRandomTransaction generates a randomized valid ETH transaction
func getRandomTransaction(t *testing.T, gasLimit uint64) *ethTypes.Transaction {
	privateKey, err := crypto.HexToECDSA(TEST_PRIVATE_KEY)
	require.NoError(t, err)

	chainId, _ := new(big.Int).SetString(CHAIN_ID, 10)
	txValue := big.NewInt(1000000000000000000)
	gasPrice := big.NewInt(30000000000)
	toAddress := common.HexToAddress(TEST_TO_ADDRESS)
	data := make([]byte, 16)
	_, err = rand.Read(data)
	require.NoError(t, err)

	tx := ethTypes.NewTx(&ethTypes.LegacyTx{
		Nonce:    lastNonce,
		To:       &toAddress,
		Value:    txValue,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})
	lastNonce++

	signedTx, err := ethTypes.SignTx(tx, ethTypes.NewEIP155Signer(chainId), privateKey)
	require.NoError(t, err)
	return signedTx
}
