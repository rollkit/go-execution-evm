package execution

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
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
func NewEngineAPIExecutionClient(proxyConfig *proxy_json_rpc.Config, ethURL, engineURL string, genesisHash common.Hash, feeRecipient common.Address) (*EngineAPIExecutionClient, error) {
	proxyClient := proxy_json_rpc.NewClient()
	proxyClient.SetConfig(proxyConfig)

	ethClient, err := ethclient.Dial(ethURL)
	if err != nil {
		return nil, err
	}

	engineClient, err := rpc.Dial(engineURL)
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
func (c *EngineAPIExecutionClient) InitChain(genesisTime time.Time, initialHeight uint64, chainID string) (execution_types.Hash, uint64, error) {
	ctx := context.Background()

	var forkchoiceResult map[string]interface{}
	err := c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV1",
		map[string]interface{}{
			"headBlockHash":      c.genesisHash,
			"safeBlockHash":      c.genesisHash,
			"finalizedBlockHash": c.genesisHash,
		},
		map[string]interface{}{
			"timestamp":             genesisTime.Unix(),
			"prevRandao":            common.Hash{},
			"suggestedFeeRecipient": c.feeRecipient,
		},
	)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_forkchoiceUpdatedV1 failed: %w", err)
	}

	payloadID, ok := forkchoiceResult["payloadId"].(string)
	if !ok {
		return execution_types.Hash{}, 0, ErrNilPayloadStatus
	}

	var payloadResult map[string]interface{}
	err = c.engineClient.CallContext(ctx, &payloadResult, "engine_getPayloadV1", payloadID)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_getPayloadV1 failed: %w", err)
	}

	stateRoot := common.HexToHash(payloadResult["stateRoot"].(string))
	gasLimit := uint64(payloadResult["gasLimit"].(float64))
	var rollkitStateRoot execution_types.Hash
	copy(rollkitStateRoot[:], stateRoot[:])
	return rollkitStateRoot, gasLimit, nil
}

// GetTxs retrieves transactions from the transaction pool
func (c *EngineAPIExecutionClient) GetTxs() ([]execution_types.Tx, error) {
	ctx := context.Background()

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
func (c *EngineAPIExecutionClient) ExecuteTxs(txs []execution_types.Tx, height uint64, timestamp time.Time, prevStateRoot execution_types.Hash) (execution_types.Hash, uint64, error) {
	ctx := context.Background()

	ethTxs := make([][]byte, len(txs))
	for i, tx := range txs {
		ethTxs[i] = tx
	}

	// call engine_newPayloadV1 with the txs
	var newPayloadResult map[string]interface{}
	err := c.engineClient.CallContext(ctx, &newPayloadResult, "engine_newPayloadV1", map[string]interface{}{
		"parentHash":   common.BytesToHash(prevStateRoot[:]),
		"timestamp":    timestamp.Unix(),
		"prevRandao":   c.derivePrevRandao(height),
		"feeRecipient": c.feeRecipient,
		"transactions": ethTxs,
	})
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_newPayloadV1 failed: %w", err)
	}

	status, ok := newPayloadResult["status"].(string)
	if !ok || PayloadStatus(status) != PayloadStatusValid {
		return execution_types.Hash{}, 0, ErrInvalidPayloadStatus
	}

	// update fork choice
	var forkchoiceResult map[string]interface{}
	err = c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV1",
		map[string]interface{}{
			"headBlockHash":      common.BytesToHash(prevStateRoot[:]),
			"safeBlockHash":      common.BytesToHash(prevStateRoot[:]),
			"finalizedBlockHash": common.BytesToHash(prevStateRoot[:]),
		},
		map[string]interface{}{
			"timestamp":             timestamp.Unix(),
			"prevRandao":            c.derivePrevRandao(height),
			"suggestedFeeRecipient": c.feeRecipient,
		},
	)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_forkchoiceUpdatedV1 failed: %w", err)
	}

	// get the execution results
	var payloadResult map[string]interface{}
	payloadID, ok := forkchoiceResult["payloadId"].(string)
	if !ok {
		return execution_types.Hash{}, 0, ErrNilPayloadStatus
	}

	err = c.engineClient.CallContext(ctx, &payloadResult, "engine_getPayloadV1", payloadID)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_getPayloadV1 failed: %w", err)
	}

	newStateRoot := common.HexToHash(payloadResult["stateRoot"].(string))
	gasUsed := uint64(payloadResult["gasUsed"].(float64))
	var rollkitNewStateRoot execution_types.Hash
	copy(rollkitNewStateRoot[:], newStateRoot[:])
	return rollkitNewStateRoot, gasUsed, nil
}

// SetFinal marks a block at the given height as final
func (c *EngineAPIExecutionClient) SetFinal(height uint64) error {
	ctx := context.Background()

	block, err := c.ethClient.BlockByNumber(ctx, big.NewInt(int64(height)))
	if err != nil {
		return fmt.Errorf("failed to get block at height %d: %w", height, err)
	}

	var forkchoiceResult map[string]interface{}
	err = c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV1",
		map[string]interface{}{
			"headBlockHash":      block.Hash(),
			"safeBlockHash":      block.Hash(),
			"finalizedBlockHash": block.Hash(),
		},
		nil, // No payload attributes for finalization
	)
	if err != nil {
		return fmt.Errorf("engine_forkchoiceUpdatedV1 failed for finalization: %w", err)
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
