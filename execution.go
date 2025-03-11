package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/golang-jwt/jwt/v5"

	execution "github.com/rollkit/go-execution"
	execution_types "github.com/rollkit/go-execution/types"
)

var (
	// ErrNilPayloadStatus indicates that PayloadID returned by EVM was nil
	ErrNilPayloadStatus = errors.New("nil payload status")
	// ErrInvalidPayloadStatus indicates that EVM returned status != VALID
	ErrInvalidPayloadStatus = errors.New("invalid payload status")
)

// Ensure EngineAPIExecutionClient implements the execution.Execute interface
var _ execution.Executor = (*PureEngineClient)(nil)

// PureEngineClient represents a client that interacts with an Ethereum execution engine
// through the Engine API. It manages connections to both the engine and standard Ethereum
// APIs, and maintains state related to block processing.
type PureEngineClient struct {
	engineClient *rpc.Client       // Client for Engine API calls
	ethClient    *ethclient.Client // Client for standard Ethereum API calls
	genesisHash  common.Hash       // Hash of the genesis block
	feeRecipient common.Address    // Address to receive transaction fees
	payloadID    *engine.PayloadID // ID of the current execution payload being processed
}

// NewEngineAPIExecutionClient creates a new instance of EngineAPIExecutionClient
func NewPureEngineExecutionClient(
	ethURL,
	engineURL string,
	jwtSecret string,
	genesisHash common.Hash,
	feeRecipient common.Address,
) (*PureEngineClient, error) {
	ethClient, err := ethclient.Dial(ethURL)
	if err != nil {
		return nil, err
	}

	secret, err := decodeSecret(jwtSecret)
	if err != nil {
		return nil, err
	}

	engineClient, err := rpc.DialOptions(context.Background(), engineURL,
		rpc.WithHTTPAuth(func(h http.Header) error {
			authToken, err := getAuthToken(secret)
			if err != nil {
				return err
			}

			if authToken != "" {
				h.Set("Authorization", "Bearer "+authToken)
			}
			return nil
		}))
	if err != nil {
		return nil, err
	}

	return &PureEngineClient{
		engineClient: engineClient,
		ethClient:    ethClient,
		genesisHash:  genesisHash,
		feeRecipient: feeRecipient,
	}, nil
}

func (c *PureEngineClient) InitChain(ctx context.Context, genesisTime time.Time, initialHeight uint64, chainID string) (execution_types.Hash, uint64, error) {
	// Acknowledge the genesis block
	var forkchoiceResult engine.ForkChoiceResponse
	err := c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		engine.ForkchoiceStateV1{
			HeadBlockHash:      c.genesisHash,
			SafeBlockHash:      c.genesisHash,
			FinalizedBlockHash: c.genesisHash,
		},
		nil,
	)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("engine_forkchoiceUpdatedV3 failed: %w", err)
	}

	// Start building the first block
	err = c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		engine.ForkchoiceStateV1{
			HeadBlockHash:      c.genesisHash,
			SafeBlockHash:      c.genesisHash,
			FinalizedBlockHash: c.genesisHash,
		},
		engine.PayloadAttributes{
			Timestamp:             uint64(genesisTime.Unix()), //nolint:gosec // disable G115
			Random:                common.Hash{},              // TODO(tzdybal): this probably shouldn't be 0
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

	c.payloadID = forkchoiceResult.PayloadID

	_, stateRoot, gasLimit, err := c.getBlockInfo(ctx, 0)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("failed to get genesis block info: %w", err)
	}

	return stateRoot[:], gasLimit, nil
}

func (c *PureEngineClient) GetTxs(ctx context.Context) ([]execution_types.Tx, error) {
	var payloadResult engine.ExecutionPayloadEnvelope
	err := c.engineClient.CallContext(ctx, &payloadResult, "engine_getPayloadV3", c.payloadID)
	if err != nil {
		return nil, fmt.Errorf("engine_getPayloadV3 failed: %w", err)
	}

	// Store the original transactions
	originalTxs := payloadResult.ExecutionPayload.Transactions

	// Clear transactions before serializing
	payloadResult.ExecutionPayload.Transactions = [][]byte{}

	jsonPayloadResult, err := json.Marshal(payloadResult)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize payloadResult: %w", err)
	}

	// Create the result with serialized payload as first tx, followed by original transactions
	txs := make([]execution_types.Tx, len(originalTxs)+1)
	txs[0] = jsonPayloadResult
	for i, tx := range originalTxs {
		txs[i+1] = tx
	}

	return txs, nil
}

func (c *PureEngineClient) ExecuteTxs(ctx context.Context, txs []execution_types.Tx, blockHeight uint64, timestamp time.Time, prevStateRoot execution_types.Hash) (updatedStateRoot execution_types.Hash, maxBytes uint64, err error) {
	var payloadResult engine.ExecutionPayloadEnvelope
	// First tx is the serialized payload
	firstTx := txs[0]
	err = json.Unmarshal(firstTx, &payloadResult)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("failed to deserialize first transaction as ExecutionPayload: %w", err)
	}

	// Add transactions from txs to the payload (skip the first one which is the payload itself)
	payloadResult.ExecutionPayload.Transactions = make([][]byte, len(txs)-1)
	for i := 1; i < len(txs); i++ {
		payloadResult.ExecutionPayload.Transactions[i-1] = txs[i]
	}

	var newPayloadResult engine.PayloadStatusV1
	err = c.engineClient.CallContext(ctx, &newPayloadResult, "engine_newPayloadV3",
		payloadResult.ExecutionPayload,
		[]string{}, // No blob hashes
		c.genesisHash.Hex(),
	)

	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("new payload submission failed: %w", err)
	}

	if newPayloadResult.Status != engine.VALID {
		return execution_types.Hash{}, 0, fmt.Errorf("new payload submission failed with: %s", *newPayloadResult.ValidationError)
	}

	// forkchoice update
	blockHash := payloadResult.ExecutionPayload.BlockHash
	var forkchoiceResult engine.ForkChoiceResponse
	err = c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		engine.ForkchoiceStateV1{
			HeadBlockHash: blockHash,
			SafeBlockHash: blockHash,
			// FinalizedBlockHash: blockHash,
		},
		&engine.PayloadAttributes{
			Timestamp:             uint64(time.Now().Unix()), //nolint:gosec // disable G115
			Random:                c.derivePrevRandao(blockHeight),
			SuggestedFeeRecipient: c.feeRecipient,
			BeaconRoot:            &c.genesisHash,
			Withdrawals:           []*types.Withdrawal{},
		},
	)
	if err != nil {
		return nil, 0, fmt.Errorf("forkchoice update failed with error: %w", err)
	}

	if forkchoiceResult.PayloadStatus.Status != engine.VALID {
		return nil, 0, ErrInvalidPayloadStatus
	}

	c.payloadID = forkchoiceResult.PayloadID

	return payloadResult.ExecutionPayload.StateRoot.Bytes(), payloadResult.ExecutionPayload.GasLimit, nil
}

func (c *PureEngineClient) SetFinal(ctx context.Context, blockHeight uint64) error {
	blockHash, _, _, err := c.getBlockInfo(ctx, blockHeight)
	if err != nil {
		return fmt.Errorf("failed to get block info: %w", err)
	}

	var forkchoiceResult engine.ForkChoiceResponse
	err = c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		engine.ForkchoiceStateV1{
			HeadBlockHash:      blockHash,
			SafeBlockHash:      blockHash,
			FinalizedBlockHash: blockHash,
		},
		nil,
	)
	if err != nil {
		return fmt.Errorf("forkchoice update failed with error: %w", err)
	}

	if forkchoiceResult.PayloadStatus.Status != engine.VALID {
		return ErrInvalidPayloadStatus
	}

	return nil
}

func (c *PureEngineClient) derivePrevRandao(blockHeight uint64) common.Hash {
	return common.BigToHash(big.NewInt(int64(blockHeight))) //nolint:gosec // disable G115
}

func (c *PureEngineClient) getBlockInfo(ctx context.Context, height uint64) (common.Hash, common.Hash, uint64, error) {
	header, err := c.ethClient.HeaderByNumber(ctx, big.NewInt(int64(height)))
	if err != nil {
		return common.Hash{}, common.Hash{}, 0, fmt.Errorf("failed to get block at height %d: %w", height, err)
	}

	return header.Hash(), header.Root, header.GasLimit, nil
}
func decodeSecret(jwtSecret string) ([]byte, error) {
	secret, err := hex.DecodeString(strings.TrimPrefix(jwtSecret, "0x"))
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT secret: %w", err)
	}
	return secret, nil
}

func getAuthToken(jwtSecret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour * 1).Unix(), // Expires in 1 hour
		"iat": time.Now().Unix(),
	})

	// Sign the token with the decoded secret
	authToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}
	return authToken, nil
}
