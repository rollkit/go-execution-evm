package execution

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/golang-jwt/jwt"
	execution "github.com/rollkit/go-execution"
	proxy_json_rpc "github.com/rollkit/go-execution/proxy/jsonrpc"
	execution_types "github.com/rollkit/go-execution/types"
)

type PayloadStatus string

const (
	PayloadStatusValid   PayloadStatus = "VALID"
	PayloadStatusInvalid PayloadStatus = "INVALID"
	PayloadStatusSyncing PayloadStatus = "SYNCING"
)

var (
	ErrNilPayloadStatus     = errors.New("nil payload status")
	ErrInvalidPayloadStatus = errors.New("invalid payload status")
)

// Ensure EngineAPIExecutionClient implements the execution.Execute interface
var _ execution.Executor = (*EngineAPIExecutionClient)(nil)

// EngineAPIExecutionClient implements the execution.Execute interface
type EngineAPIExecutionClient struct {
	proxyClient  *proxy_json_rpc.Client
	engineClient *rpc.Client // engine api
	ethClient    *ethclient.Client
	genesisHash  common.Hash
	feeRecipient common.Address
}

// NewEngineAPIExecutionClient creates a new instance of EngineAPIExecutionClient
func NewEngineAPIExecutionClient(proxyConfig *proxy_json_rpc.Config, ethURL, engineURL string, jwtSecret string, genesisHash common.Hash, feeRecipient common.Address) (*EngineAPIExecutionClient, error) {
	proxyClient := proxy_json_rpc.NewClient()
	proxyClient.SetConfig(proxyConfig)

	ethClient, err := ethclient.Dial(ethURL)
	if err != nil {
		return nil, err
	}

	authToken := ""
	if jwtSecret != "" {
		// Decode hex secret to bytes
		secret, err := hex.DecodeString(jwtSecret)
		if err != nil {
			return nil, err
		}

		// Create a new token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp": time.Now().Add(time.Hour * 1).Unix(), // Expires in 1 hour
			"iat": time.Now().Unix(),
		})

		// Sign the token with the decoded secret
		authToken, err = token.SignedString(secret)
		if err != nil {
			return nil, err
		}
	}

	engineClient, err := rpc.DialOptions(context.Background(), engineURL,
		rpc.WithHTTPAuth(func(h http.Header) error {
			if authToken != "" {
				h.Set("Authorization", "Bearer "+authToken)
			}
			return nil
		}))
	if err != nil {
		return nil, err
	}

	return &EngineAPIExecutionClient{
		proxyClient:  proxyClient,
		engineClient: engineClient,
		ethClient:    ethClient,
		genesisHash:  genesisHash,
		feeRecipient: feeRecipient,
	}, nil
}

// Start starts the execution client
func (c *EngineAPIExecutionClient) Start(url string) error {
	return c.proxyClient.Start(url)
}

// Stop stops the execution client and closes all connections
func (c *EngineAPIExecutionClient) Stop() {
	c.proxyClient.Stop()

	if c.engineClient != nil {
		c.engineClient.Close()
	}

	if c.ethClient != nil {
		c.ethClient.Close()
	}
}

// InitChain initializes the blockchain with genesis information
func (c *EngineAPIExecutionClient) InitChain(ctx context.Context, genesisTime time.Time, initialHeight uint64, chainID string) (execution_types.Hash, uint64, error) {
	var forkchoiceResult map[string]interface{}
	
	err := c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		map[string]interface{}{
			"headBlockHash":      c.genesisHash,
			"safeBlockHash":      c.genesisHash,
			"finalizedBlockHash": c.genesisHash,
		},
		map[string]interface{}{
			"timestamp":             fmt.Sprintf("0x%X", genesisTime.Unix()),
			"prevRandao":            common.Hash{},
			"suggestedFeeRecipient": c.feeRecipient,
			"parentBeaconBlockRoot": common.Hash{},
		},
	)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_forkchoiceUpdatedV3 failed: %w", err)
	}

	payloadID, ok := forkchoiceResult["payloadId"].(string)
	if !ok {
		return execution_types.Hash{}, 0, ErrNilPayloadStatus
	}

	var payloadResult map[string]interface{}
	err = c.engineClient.CallContext(ctx, &payloadResult, "engine_getPayloadV3", payloadID)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_getPayloadV3 failed: %w", err)
	}

	executionPayload := payloadResult["executionPayload"].(map[string]interface{})
	stateRoot := common.HexToHash(executionPayload["stateRoot"].(string))

	gasLimitHex := executionPayload["gasLimit"].(string)
	gasLimit := new(big.Int)
	gasLimit.SetString(gasLimitHex[2:], 16)

	var rollkitStateRoot execution_types.Hash
	copy(rollkitStateRoot[:], stateRoot[:])
	return rollkitStateRoot, gasLimit.Uint64(), nil
}

// GetTxs retrieves transactions from the transaction pool
func (c *EngineAPIExecutionClient) GetTxs(ctx context.Context) ([]execution_types.Tx, error) {
	var result struct {
		Pending map[string]map[string]*types.Transaction `json:"pending"`
		Queued  map[string]map[string]*types.Transaction `json:"queued"`
	}
	err := c.ethClient.Client().CallContext(ctx, &result, "txpool_content")
	if err != nil {
		return nil, fmt.Errorf("failed to get tx pool content: %w", err)
	}

	var txs []execution_types.Tx

	// add pending txs
	for _, accountTxs := range result.Pending {
		for _, tx := range accountTxs {
			txBytes, err := tx.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal transaction: %w", err)
			}
			txs = append(txs, execution_types.Tx(txBytes))
		}
	}

	// add queued txs
	for _, accountTxs := range result.Queued {
		for _, tx := range accountTxs {
			txBytes, err := tx.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("failed to marshal transaction: %w", err)
			}
			txs = append(txs, execution_types.Tx(txBytes))
		}
	}
	return txs, nil
}

// ExecuteTxs executes the given transactions and returns the new state root and gas used
func (c *EngineAPIExecutionClient) ExecuteTxs(ctx context.Context, txs []execution_types.Tx, height uint64, timestamp time.Time, prevStateRoot execution_types.Hash) (execution_types.Hash, uint64, error) {
	ethTxs := make([][]byte, len(txs))
	for i, tx := range txs {
		ethTxs[i] = tx
	}

	var newPayloadResult map[string]interface{}
	err := c.engineClient.CallContext(ctx, &newPayloadResult, "engine_newPayloadV3", map[string]interface{}{
		"parentHash":                  common.BytesToHash(prevStateRoot[:]),
		"timestamp":                   timestamp.Unix(),
		"prevRandao":                  c.derivePrevRandao(height),
		"feeRecipient":                c.feeRecipient,
		"transactions":                ethTxs,
		"expectedBlobVersionedHashes": []string{},
		"parentBeaconBlockRoot":       common.Hash{},
	})
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_newPayloadV3 failed: %w", err)
	}

	status, ok := newPayloadResult["status"].(string)
	if !ok || PayloadStatus(status) != PayloadStatusValid {
		return execution_types.Hash{}, 0, ErrInvalidPayloadStatus
	}

	// update fork choice
	var forkchoiceResult map[string]interface{}
	err = c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		map[string]interface{}{
			"headBlockHash":      common.BytesToHash(prevStateRoot[:]),
			"safeBlockHash":      common.BytesToHash(prevStateRoot[:]),
			"finalizedBlockHash": common.BytesToHash(prevStateRoot[:]),
		},
		map[string]interface{}{
			"timestamp":             timestamp.Unix(),
			"prevRandao":            c.derivePrevRandao(height),
			"suggestedFeeRecipient": c.feeRecipient,
			"parentBeaconBlockRoot": common.Hash{},
		},
	)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_forkchoiceUpdatedV3 failed: %w", err)
	}

	// get the execution results
	var payloadResult map[string]interface{}
	payloadID, ok := forkchoiceResult["payloadId"].(string)
	if !ok {
		return execution_types.Hash{}, 0, ErrNilPayloadStatus
	}

	err = c.engineClient.CallContext(ctx, &payloadResult, "engine_getPayloadV3", payloadID)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_getPayloadV3 failed: %w", err)
	}

	executionPayload := payloadResult["executionPayload"].(map[string]interface{})
	newStateRoot := common.HexToHash(executionPayload["stateRoot"].(string))

	gasUsedHex := executionPayload["gasUsed"].(string)
	gasUsed := new(big.Int)
	gasUsed.SetString(gasUsedHex[2:], 16)

	var rollkitNewStateRoot execution_types.Hash
	copy(rollkitNewStateRoot[:], newStateRoot[:])
	return rollkitNewStateRoot, gasUsed.Uint64(), nil
}

// SetFinal marks a block at the given height as final
func (c *EngineAPIExecutionClient) SetFinal(ctx context.Context, height uint64) error {
	block, err := c.ethClient.BlockByNumber(ctx, big.NewInt(int64(height)))
	if err != nil {
		return fmt.Errorf("failed to get block at height %d: %w", height, err)
	}

	var forkchoiceResult map[string]interface{}
	err = c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		map[string]interface{}{
			"headBlockHash":      block.Hash(),
			"safeBlockHash":      block.Hash(),
			"finalizedBlockHash": block.Hash(),
		},
		map[string]interface{}{
			"parentBeaconBlockRoot": common.Hash{},
		},
	)
	if err != nil {
		return fmt.Errorf("engine_forkchoiceUpdatedV3 failed for finalization: %w", err)
	}

	payloadStatus, ok := forkchoiceResult["payloadStatus"].(map[string]interface{})
	if !ok {
		return ErrNilPayloadStatus
	}

	status, ok := payloadStatus["status"].(string)
	if !ok || PayloadStatus(status) != PayloadStatusValid {
		return ErrInvalidPayloadStatus
	}

	return nil
}

// derivePrevRandao generates a deterministic prevRandao value based on block height
func (c *EngineAPIExecutionClient) derivePrevRandao(blockHeight uint64) common.Hash {
	return common.BigToHash(big.NewInt(int64(blockHeight)))
}
