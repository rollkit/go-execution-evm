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

	"github.com/rollkit/go-execution/test"
	"github.com/stretchr/testify/suite"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/ethereum/go-ethereum/common"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/rollkit/go-execution/types"
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

func generateJWTSecret() (string, error) {
	jwtSecret := make([]byte, 32)
	_, err := rand.Read(jwtSecret)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return hex.EncodeToString(jwtSecret), nil
}

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
			cli, err := testcontainers.NewDockerClient()
			if err == nil {
				reader, err := cli.ContainerLogs(context.Background(), "reth", container.LogsOptions{
					ShowStdout: true,
					ShowStderr: true,
					Follow:     false,
				})
				if err == nil {
					defer reader.Close()
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

func TestExecutionClientLifecycle(t *testing.T) {
	jwtSecret := setupTestRethEngine(t)

	initialHeight := uint64(0)
	genesisHash := common.HexToHash(GENESIS_HASH)
	genesisTime := time.Now().UTC().Truncate(time.Second)
	genesisStateroot := common.HexToHash(GENESIS_STATEROOT)
	rollkitGenesisStateRoot := types.Hash(genesisStateroot[:])

	executionClient, err := NewPureEngineExecutionClient(
		TEST_ETH_URL,
		TEST_ENGINE_URL,
		jwtSecret,
		genesisHash,
		common.Address{},
	)
	require.NoError(t, err)

	require.True(t, t.Run("InitChain", func(t *testing.T) {
		stateRoot, gasLimit, err := executionClient.InitChain(context.Background(), genesisTime, initialHeight, CHAIN_ID)
		require.NoError(t, err)

		require.Equal(t, rollkitGenesisStateRoot, stateRoot)
		require.Equal(t, uint64(1000000), gasLimit)
	}))

	require.True(t, t.Run("InitChain_InvalidPayloadTimestamp", func(t *testing.T) {
		blockTime := time.Date(2024, 3, 13, 13, 54, 0, 0, time.UTC) // pre-cancun timestamp not supported
		_, _, err := executionClient.InitChain(context.Background(), blockTime, initialHeight, CHAIN_ID)
		// payload timestamp is not within the cancun timestamp
		require.Error(t, err)
		require.ErrorContains(t, err, "Unsupported fork")
	}))

	gasLimit := uint64(22000)
	signedTx := getRandomTransaction(t, gasLimit)

	rSignedTx, sSignedTx, vSignedTx := signedTx.RawSignatureValues()

	submitTransaction(t, signedTx)

	require.True(t, t.Run("GetTxs", func(t *testing.T) {
		txs, err := executionClient.GetTxs(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 1, len(txs))

		txResp := ethTypes.Transaction{}
		err = txResp.UnmarshalBinary(txs[0])
		require.NoError(t, err)

		assert.Equal(t, signedTx.Nonce(), txResp.Nonce())
		assert.Equal(t, signedTx.Value(), txResp.Value())
		assert.Equal(t, signedTx.To(), txResp.To())
		assert.Equal(t, signedTx.GasPrice(), txResp.GasPrice())
		r, s, v := txResp.RawSignatureValues()
		assert.Equal(t, rSignedTx, r)
		assert.Equal(t, sSignedTx, s)
		assert.Equal(t, vSignedTx, v)
	}))

	txBytes, err := signedTx.MarshalBinary()
	require.NoError(t, err)

	blockHeight := uint64(1)
	blockTime := genesisTime.Add(10 * time.Second)

	require.True(t, t.Run("ExecuteTxs", func(t *testing.T) {
		stateRoot, maxGas, err := executionClient.ExecuteTxs(context.Background(), []types.Tx{txBytes}, blockHeight, blockTime, rollkitGenesisStateRoot)
		require.NoError(t, err)
		assert.LessOrEqual(t, gasLimit, maxGas)
		assert.NotEqual(t, rollkitGenesisStateRoot, stateRoot)
	}))
}

func submitTransaction(t *testing.T, signedTx *ethTypes.Transaction) {
	rpcClient, err := ethclient.Dial(TEST_ETH_URL)
	require.NoError(t, err)
	err = rpcClient.SendTransaction(context.Background(), signedTx)
	require.NoError(t, err)
}

var lastNonce uint64

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

type evmSuite struct {
	test.ExecutorSuite
}

func (s *evmSuite) GetRandomTxs(n int) []types.Tx {
	txs := make([]types.Tx, n)
	for i := 0; i < n; i++ {
		tx := getRandomTransaction(s.T(), 22000)

		bytes, err := tx.MarshalBinary()
		require.NoError(s.T(), err)
		txs[i] = bytes
	}
	return txs
}

func (s *evmSuite) InjectTxs(txs []types.Tx) error {
	for _, txBytes := range txs {
		var tx ethTypes.Transaction
		err := tx.UnmarshalBinary(txBytes)
		s.Require().NoError(err)
		submitTransaction(s.T(), &tx)
	}
	return nil
}

func (s *evmSuite) SetupTest() {
	jwtSecret := setupTestRethEngine(s.T())

	genesisHash := common.HexToHash(GENESIS_HASH)

	executionClient, err := NewPureEngineExecutionClient(
		TEST_ETH_URL,
		TEST_ENGINE_URL,
		jwtSecret,
		genesisHash,
		common.Address{},
	)
	s.Require().NoError(err)
	s.Exec = executionClient
	s.TxInjector = s
	lastNonce = uint64(0)
}

func TestRunCommonSuite(t *testing.T) {
	suite.Run(t, new(evmSuite))
}
