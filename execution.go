package execution

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"encoding/hex"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/beacon/engine"

	"github.com/golang-jwt/jwt/v5"
	execution "github.com/rollkit/go-execution"
	proxy_json_rpc "github.com/rollkit/go-execution/proxy/jsonrpc"
	execution_types "github.com/rollkit/go-execution/types"
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
func NewEngineAPIExecutionClient(
	proxyConfig *proxy_json_rpc.Config,
	ethURL,
	engineURL string,
	jwtSecret string,
	genesisHash common.Hash,
	feeRecipient common.Address,
) (*EngineAPIExecutionClient, error) {
	proxyClient := proxy_json_rpc.NewClient()
	proxyClient.SetConfig(proxyConfig)

	ethClient, err := ethclient.Dial(ethURL)
	if err != nil {
		return nil, err
	}

	authToken := ""
	if jwtSecret != "" {
		secret, err := hex.DecodeString(jwtSecret)
		if err != nil {
			return nil, err
		}

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
		ethClient.Close() // Clean up eth client if engine client fails
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
	var forkchoiceResult ForkchoiceUpdatedResponse
	err := c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		ForkchoiceState{
			HeadBlockHash:      c.genesisHash,
			SafeBlockHash:      c.genesisHash,
			FinalizedBlockHash: c.genesisHash,
		},
		map[string]interface{}{
			"timestamp":             fmt.Sprintf("0x%X", genesisTime.Unix()),
			"prevRandao":            common.Hash{},
			"suggestedFeeRecipient": c.feeRecipient,
			"parentBeaconBlockRoot": common.Hash{},
			"withdrawals":           []struct{}{},
		},
	)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_forkchoiceUpdatedV3 failed: %w", err)
	}

	if forkchoiceResult.PayloadID == nil {
		return execution_types.Hash{}, 0, ErrNilPayloadStatus
	}

	var payloadResult PayloadResponse
	err = c.engineClient.CallContext(ctx, &payloadResult, "engine_getPayloadV3", *forkchoiceResult.PayloadID)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_getPayloadV3 failed: %w", err)
	}

	executionPayload := payloadResult["executionPayload"].(map[string]interface{})
	stateRoot := common.HexToHash(payloadResult.ExecutionPayload.StateRoot)
	rollkitStateRoot := execution_types.Hash(stateRoot[:])

	gasLimitHex := executionPayload["gasLimit"].(string)
	
	gasLimit := new(big.Int)
	gasLimit.SetString(strings.TrimPrefix(payloadResult.ExecutionPayload.GasLimit, "0x"), 16)

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
	ethTxs := make([]*types.Transaction, len(txs))
	for i, tx := range txs {
		ethTxs[i] = new(types.Transaction)
		err := ethTxs[i].UnmarshalBinary(tx)
		if err != nil {
			return execution_types.Hash{}, 0, fmt.Errorf("engine_newPayloadV3 failed: %s", err.Error())
		}
	}

	txsPayload := make([]string, len(txs))
	for i, tx := range ethTxs {
		buf := bytes.Buffer{}
		err := tx.EncodeRLP(&buf)
		if err != nil {
			return execution_types.Hash{}, 0, fmt.Errorf("error RLP encoding tx: %s", err.Error())
		}

		txsPayload[i] = fmt.Sprintf("0x%x", buf.Bytes())
	}

	blockHeader := types.Header{
		Root:          common.Hash(prevStateRoot),
		ParentHash:    common.BytesToHash(prevStateRoot[:]),
		UncleHash:     types.EmptyUncleHash,
		Time:          uint64(1731729558), // timestamp.Unix
		Coinbase:      c.feeRecipient,
		MixDigest:     c.derivePrevRandao(height),
		BlobGasUsed:   new(uint64),
		ExcessBlobGas: new(uint64),
		ReceiptHash:   common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000000"),
		Bloom:         types.Bloom{},
		Number:        big.NewInt(int64(height)),
		GasLimit:      30000000,
		GasUsed:       20000000,
		Extra:         hexutil.Bytes("0x"),
		BaseFee:       big.NewInt(7),
		TxHash:        types.DeriveSha(types.Transactions(ethTxs), trie.NewStackTrie(nil)),
		Difficulty:    big.NewInt(0),
		Nonce:         types.BlockNonce{},
	}

	logsBloomStr, err := blockHeader.Bloom.MarshalText()
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("invalid logs bloom: %w", err)
	}
engine.
	var newPayloadResult map[string]interface{}
	err = c.engineClient.CallContext(ctx, &newPayloadResult, "engine_newPayloadV3",
		engine.PayloadV3
		map[string]interface{}{
			"stateRoot":     blockHeader.Root.Hex(),
			"parentHash":    blockHeader.ParentHash.Hex(),
			"timestamp":     hexutil.EncodeUint64(blockHeader.Time),
			"prevRandao":    blockHeader.MixDigest.Hex(),
			"feeRecipient":  blockHeader.Coinbase.Hex(),
			"transactions":  txsPayload,
			"blobGasUsed":   hexutil.EncodeUint64(*blockHeader.BlobGasUsed),
			"excessBlobGas": hexutil.EncodeUint64(*blockHeader.ExcessBlobGas),
			"withdrawals":   []struct{}{},
			"receiptsRoot":  blockHeader.ReceiptHash.Hex(),
			"logsBloom":     string(logsBloomStr),
			"blockNumber":   hexutil.EncodeBig(blockHeader.Number),
			"gasLimit":      hexutil.EncodeUint64(blockHeader.GasLimit),
			"gasUsed":       hexutil.EncodeUint64(blockHeader.GasUsed),
			"extraData":     "0x",
			"baseFeePerGas": hexutil.EncodeBig(blockHeader.BaseFee),
			"blockHash":     blockHeader.Hash().Hex(), // Keccak256(RLP(ExecutionBlockHeader))
		},
		// Expected blob versioned hashes
		[]string{
			"0x0000000000000000000000000000000000000000000000000000000000000000",
		},
		// Root of the parent beacon block
		c.genesisHash.Hex(),
	type newPayloadResult struct {
		Status PayloadStatus `json:"status"`
	}
	err := c.engineClient.CallContext(ctx, &newPayloadResult, "engine_newPayloadV3",
		NewPayloadRequest{
			ParentHash:                  common.BytesToHash(prevStateRoot[:]),
			Timestamp:                   timestamp.Unix(),
			PrevRandao:                  c.derivePrevRandao(height),
			FeeRecipient:                c.feeRecipient,
			Transactions:                ethTxs,
			ExpectedBlobVersionedHashes: []string{},
			ParentBeaconBlockRoot:       common.Hash{},
		},
	)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_newPayloadV3 failed: %s", err.Error())
	}

	if newPayloadResult.Status != PayloadStatusValid {
		return execution_types.Hash{}, 0, ErrInvalidPayloadStatus
	}

	var forkchoiceResult ForkchoiceUpdatedResponse
	err = c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		ForkchoiceState{
			HeadBlockHash:      common.BytesToHash(prevStateRoot[:]),
			SafeBlockHash:      common.BytesToHash(prevStateRoot[:]),
			FinalizedBlockHash: common.BytesToHash(prevStateRoot[:]),
		},
		PayloadAttributes{
			Timestamp:             timestamp.Unix(),
			PrevRandao:            c.derivePrevRandao(height),
			SuggestedFeeRecipient: c.feeRecipient,
			ParentBeaconBlockRoot: common.Hash{},
		},
	)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_forkchoiceUpdatedV3 failed: %w", err)
	}

	if forkchoiceResult.PayloadID == nil {
		return execution_types.Hash{}, 0, ErrNilPayloadStatus
	}

	var payloadResult PayloadResponse
	err = c.engineClient.CallContext(ctx, &payloadResult, "engine_getPayloadV3", *forkchoiceResult.PayloadID)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_getPayloadV3 failed: %w", err)
	}

	newStateRoot := common.HexToHash(payloadResult.ExecutionPayload.StateRoot)
	gasUsed := new(big.Int)
	gasUsed.SetString(strings.TrimPrefix(payloadResult.ExecutionPayload.GasUsed, "0x"), 16)

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

	var forkchoiceResult ForkchoiceUpdatedResponse
	err = c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		ForkchoiceState{
			HeadBlockHash:      block.Hash(),
			SafeBlockHash:      block.Hash(),
			FinalizedBlockHash: block.Hash(),
		},
		PayloadAttributes{
			ParentBeaconBlockRoot: common.Hash{},
		},
	)
	if err != nil {
		return fmt.Errorf("engine_forkchoiceUpdatedV3 failed for finalization: %w", err)
	}

	if forkchoiceResult.PayloadStatus.Status != PayloadStatusValid {
		return ErrInvalidPayloadStatus
	}

	return nil
}

// derivePrevRandao generates a deterministic prevRandao value based on block height
func (c *EngineAPIExecutionClient) derivePrevRandao(blockHeight uint64) common.Hash {
	return common.BigToHash(big.NewInt(int64(blockHeight)))
}
