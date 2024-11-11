package execution

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	proxy_json_rpc "github.com/rollkit/go-execution/proxy/jsonrpc"
	rollkit_types "github.com/rollkit/go-execution/types"
)

const (
	TEST_ETH_URL    = "http://localhost:8545"
	TEST_ENGINE_URL = "http://localhost:8551"

	CHAIN_ID     = "1234"
	GENESIS_HASH = "0x8bf225d50da44f60dee1c4ee6f810fe5b44723c76ac765654b6692d50459f216"
	JWT_SECRET   = "09a23c010d96caaebb21c193b85d30bbb62a9bac5bd0a684e9e91c77c811ca65"

	DOCKER_CHAIN_PATH      = "./docker/chain"     // path relative to the test file
	DOCKER_JWTSECRET_PATH  = "./docker/jwttoken/" // path relative to the test file
	DOCKER_JWT_SECRET_FILE = "testsecret.hex"
)

func setupTestRethEngine(t *testing.T) {
	t.Helper()

	chainPath, err := filepath.Abs(DOCKER_CHAIN_PATH)
	require.NoError(t, err)

	jwtSecretPath, err := filepath.Abs(DOCKER_JWTSECRET_PATH)
	require.NoError(t, err)

	err = os.WriteFile(DOCKER_JWTSECRET_PATH+DOCKER_JWT_SECRET_FILE, []byte(JWT_SECRET), 0644)
	require.NoError(t, err)

	cli, err := client.NewClientWithOpts()
	require.NoError(t, err)

	rethContainer, err := cli.ContainerCreate(context.Background(),
		&container.Config{
			Image:      "ghcr.io/paradigmxyz/reth",
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
          		--http.api "eth,net,web3" \
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
				jwtSecretPath + ":/root/jwt:ro",
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

	err = cli.ContainerStart(context.Background(), rethContainer.ID, container.StartOptions{})
	require.NoError(t, err)

	// a reasonable time to wait for the container to start!
	// do we want a more predictable elaborate code to wait for the container to be running?
	time.Sleep(50 * time.Millisecond)

	t.Cleanup(func() {
		err = cli.ContainerStop(context.Background(), rethContainer.ID, container.StopOptions{})
		require.NoError(t, err)
		err = cli.ContainerRemove(context.Background(), rethContainer.ID, container.RemoveOptions{})
		require.NoError(t, err)
		err = os.Remove(DOCKER_JWTSECRET_PATH + DOCKER_JWT_SECRET_FILE)
		require.NoError(t, err)
	})
}

func TestEngineAPIExecutionClient_engineLifecycle(t *testing.T) {
	setupTestRethEngine(t)

	genesisHash := common.HexToHash(GENESIS_HASH)
	client, err := NewEngineAPIExecutionClient(
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

	staterootHash := common.HexToHash("0x362b7d8a31e7671b0f357756221ac385790c25a27ab222dc8cbdd08944f5aea4")
	var expectedStateRoot rollkit_types.Hash
	copy(expectedStateRoot[:], staterootHash.Bytes())

	require.Equal(t, expectedStateRoot, stateRoot)
	require.Equal(t, uint64(1000000), gasLimit)
}
