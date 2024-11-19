package execution

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/trie"

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
	var forkchoiceResult engine.ForkChoiceResponse
	err := c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		engine.ForkchoiceStateV1{
			HeadBlockHash:      c.genesisHash,
			SafeBlockHash:      c.genesisHash,
			FinalizedBlockHash: c.genesisHash,
		},
		engine.PayloadAttributes{
			Timestamp:             uint64(genesisTime.Unix()),
			Random:                common.Hash{},
			SuggestedFeeRecipient: c.feeRecipient,
			BeaconRoot:            &c.genesisHash,
			Withdrawals:           []*types.Withdrawal{},
		},
	)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_forkchoiceUpdatedV3 failed: %w", err)
	}

	if forkchoiceResult.PayloadID == nil {
		return execution_types.Hash{}, 0, ErrNilPayloadStatus
	}

	var payloadResult engine.ExecutionPayloadEnvelope
	err = c.engineClient.CallContext(ctx, &payloadResult, "engine_getPayloadV3", *forkchoiceResult.PayloadID)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_getPayloadV3 failed: %w", err)
	}

	stateRoot := common.HexToHash(payloadResult.ExecutionPayload.StateRoot.Hex())
	rollkitStateRoot := execution_types.Hash(stateRoot[:])

	gasLimit := payloadResult.ExecutionPayload.GasLimit

	return rollkitStateRoot, gasLimit, nil
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

	txsPayload := make([][]byte, len(txs))
	for i, tx := range ethTxs {
		buf := bytes.Buffer{}
		err := tx.EncodeRLP(&buf)
		if err != nil {
			return execution_types.Hash{}, 0, fmt.Errorf("error RLP encoding tx: %s", err.Error())
		}

		txsPayload[i] = buf.Bytes()
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

	var newPayloadResult engine.PayloadStatusV1
	err := c.engineClient.CallContext(ctx, &newPayloadResult, "engine_newPayloadV3",
		engine.ExecutableData{
			StateRoot:     blockHeader.Root,
			ParentHash:    blockHeader.ParentHash,
			Timestamp:     blockHeader.Time,
			Random:        blockHeader.MixDigest,
			FeeRecipient:  blockHeader.Coinbase,
			Transactions:  txsPayload,
			BlobGasUsed:   blockHeader.BlobGasUsed,
			ExcessBlobGas: blockHeader.ExcessBlobGas,
			Withdrawals:   []*types.Withdrawal{},
			ReceiptsRoot:  blockHeader.ReceiptHash,
			LogsBloom:     blockHeader.Bloom[:],
			Number:        blockHeader.Number.Uint64(),
			GasLimit:      blockHeader.GasLimit,
			GasUsed:       blockHeader.GasUsed,
			ExtraData:     []byte("0x"),
			BaseFeePerGas: blockHeader.BaseFee,
			BlockHash:     blockHeader.Hash(), // Keccak256(RLP(ExecutionBlockHeader))
		},
		// Expected blob versioned hashes
		[]string{
			"0x0000000000000000000000000000000000000000000000000000000000000000",
		},
		// Root of the parent beacon block
		c.genesisHash.Hex(),
	)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_newPayloadV3 failed: %s", err.Error())
	}

	if newPayloadResult.Status != engine.VALID {
		return execution_types.Hash{}, 0, ErrInvalidPayloadStatus
	}

	var forkchoiceResult engine.ForkChoiceResponse
	err = c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		engine.ForkchoiceStateV1{
			HeadBlockHash:      common.BytesToHash(prevStateRoot[:]),
			SafeBlockHash:      common.BytesToHash(prevStateRoot[:]),
			FinalizedBlockHash: common.BytesToHash(prevStateRoot[:]),
		},
		engine.PayloadAttributes{
			Timestamp:             uint64(timestamp.Unix()),
			Random:                c.derivePrevRandao(height),
			SuggestedFeeRecipient: c.feeRecipient,
			BeaconRoot:            nil,
		},
	)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_forkchoiceUpdatedV3 failed: %w", err)
	}

	if forkchoiceResult.PayloadID == nil {
		return execution_types.Hash{}, 0, ErrNilPayloadStatus
	}

	var payloadResult engine.ExecutionPayloadEnvelope
	err = c.engineClient.CallContext(ctx, &payloadResult, "engine_getPayloadV3", *forkchoiceResult.PayloadID)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_getPayloadV3 failed: %w", err)
	}

	newStateRoot := common.HexToHash(payloadResult.ExecutionPayload.StateRoot.Hex())
	gasUsed := payloadResult.ExecutionPayload.GasUsed

	var rollkitNewStateRoot execution_types.Hash
	copy(rollkitNewStateRoot[:], newStateRoot[:])
	return rollkitNewStateRoot, gasUsed, nil
}

// SetFinal marks a block at the given height as final
func (c *EngineAPIExecutionClient) SetFinal(ctx context.Context, height uint64) error {
	block, err := c.ethClient.BlockByNumber(ctx, big.NewInt(int64(height)))
	if err != nil {
		return fmt.Errorf("failed to get block at height %d: %w", height, err)
	}

	var forkchoiceResult engine.ForkChoiceResponse
	err = c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		engine.ForkchoiceStateV1{
			HeadBlockHash:      block.Hash(),
			SafeBlockHash:      block.Hash(),
			FinalizedBlockHash: block.Hash(),
		},
		engine.PayloadAttributes{
			BeaconRoot: nil,
		},
	)
	if err != nil {
		return fmt.Errorf("engine_forkchoiceUpdatedV3 failed for finalization: %w", err)
	}

	if forkchoiceResult.PayloadStatus.Status != engine.VALID {
		return ErrInvalidPayloadStatus
	}

	return nil
}

// derivePrevRandao generates a deterministic prevRandao value based on block height
func (c *EngineAPIExecutionClient) derivePrevRandao(blockHeight uint64) common.Hash {
	return common.BigToHash(big.NewInt(int64(blockHeight)))
}
