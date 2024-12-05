package execution

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	proxy_json_rpc "github.com/rollkit/go-execution/proxy/jsonrpc"
	rollkit_types "github.com/rollkit/go-execution/types"
)

const (
	TEST_ETH_URL    = "http://localhost:8545"
	TEST_ENGINE_URL = "http://localhost:8551"

	CHAIN_ID          = "1234"
	GENESIS_HASH      = "0x8bf225d50da44f60dee1c4ee6f810fe5b44723c76ac765654b6692d50459f216"
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

	cli, err := client.NewClientWithOpts()
	require.NoError(t, err)

	t.Cleanup(func() {
		err := cli.Close()
		require.NoError(t, err)
	})

	rethContainer, err := cli.ContainerCreate(context.Background(),
		&container.Config{
			Image:      "ghcr.io/paradigmxyz/reth:v1.1.1",
			Entrypoint: []string{"/bin/sh", "-c"},
			Cmd: []string{
				`
				reth init --chain /root/chain/genesis.json && \
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
          		--debug.tip 0x8bf225d50da44f60dee1c4ee6f810fe5b44723c76ac765654b6692d50459f216 \
          		-vvvv
				`,
			},
			ExposedPorts: map[nat.Port]struct{}{
				nat.Port("8545/tcp"): {},
				nat.Port("8551/tcp"): {},
			},
		},
		&container.HostConfig{
			Binds: []string{
				chainPath + ":/root/chain:ro",
				jwtPath + ":/root/jwt:ro",
			},
			PortBindings: nat.PortMap{
				nat.Port("8545/tcp"): []nat.PortBinding{
					{
						HostIP:   "0.0.0.0",
						HostPort: "8545",
					},
				},
				nat.Port("8551/tcp"): []nat.PortBinding{
					{
						HostIP:   "0.0.0.0",
						HostPort: "8551",
					},
				},
			},
		},
		nil, nil, "reth")
	require.NoError(t, err)

	t.Cleanup(func() {
		err := cli.ContainerStop(context.Background(), rethContainer.ID, container.StopOptions{})
		require.NoError(t, err)
		err = cli.ContainerRemove(context.Background(), rethContainer.ID, container.RemoveOptions{})
		require.NoError(t, err)
	})

	err = cli.ContainerStart(context.Background(), rethContainer.ID, container.StartOptions{})
	require.NoError(t, err)

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

	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
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

					authToken, err := getAuthToken(jwtSecret)
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
	rollkitGenesisStateRoot := rollkit_types.Hash(genesisStateroot[:])

	rpcClient, err := ethclient.Dial(TEST_ETH_URL)
	require.NoError(t, err)

	executionClient, err := NewEngineAPIExecutionClient(
		&proxy_json_rpc.Config{},
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

	privateKey, err := crypto.HexToECDSA(TEST_PRIVATE_KEY)
	require.NoError(t, err)

	chainId, _ := new(big.Int).SetString(CHAIN_ID, 10)
	nonce := uint64(1)
	txValue := big.NewInt(1000000000000000000)
	gasLimit := uint64(21000)
	gasPrice := big.NewInt(30000000000)
	toAddress := common.HexToAddress(TEST_TO_ADDRESS)

	tx := types.NewTransaction(nonce, toAddress, txValue, gasLimit, gasPrice, nil)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainId), privateKey)
	require.NoError(t, err)

	rSignedTx, sSignedTx, vSignedTx := signedTx.RawSignatureValues()

	err = rpcClient.SendTransaction(context.Background(), signedTx)
	require.NoError(t, err)

	require.True(t, t.Run("GetTxs", func(t *testing.T) {
		txs, err := executionClient.GetTxs(context.Background())
		require.NoError(t, err)
		assert.Equal(t, 1, len(txs))

		txResp := types.Transaction{}
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
		newStateroot := common.HexToHash("0x362b7d8a31e7671b0f357756221ac385790c25a27ab222dc8cbdd08944f5aea4")

		stateroot, gasUsed, err := executionClient.ExecuteTxs(context.Background(), []rollkit_types.Tx{rollkit_types.Tx(txBytes)}, blockHeight, blockTime, rollkitGenesisStateRoot)
		require.NoError(t, err)
		assert.Greater(t, gasLimit, gasUsed)
		assert.Equal(t, rollkit_types.Hash(newStateroot[:]), stateroot)
	}))
}
