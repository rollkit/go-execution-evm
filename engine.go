package execution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	execution_types "github.com/rollkit/go-execution/types"
)

type PureEngineClient struct {
	engineClient *rpc.Client // engine api
	genesisHash  common.Hash
	feeRecipient common.Address
	payloadID    *engine.PayloadID
	building     bool
}

// NewEngineAPIExecutionClient creates a new instance of EngineAPIExecutionClient
func NewPureEngineExecutionClient(
	engineURL string,
	jwtSecret string,
	genesisHash common.Hash,
	feeRecipient common.Address,
) (*PureEngineClient, error) {
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
		genesisHash:  genesisHash,
		feeRecipient: feeRecipient,
	}, nil
}

func (c *PureEngineClient) InitChain(ctx context.Context, genesisTime time.Time, initialHeight uint64, chainID string) (execution_types.Hash, uint64, error) {
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
	fmt.Printf("tzdybal: %+v\n", forkchoiceResult)
	//
	//// Retrieve the Genesis Execution Payload
	//// Ensures the execution client recognizes the genesis block.
	//var payloadResult engine.ExecutionPayloadEnvelope
	//err = c.engineClient.CallContext(ctx, &payloadResult, "engine_getPayloadV3", forkchoiceResult.PayloadID)
	//if err != nil {
	//	return execution_types.Hash{}, 0, fmt.Errorf("engine_getPayloadV3 failed: %w", err)
	//}
	//stateRoot := payloadResult.ExecutionPayload.StateRoot
	//gasLimit := payloadResult.ExecutionPayload.GasLimit
	//firstPayloadID := forkchoiceResult.PayloadID

	// Start building the first block
	var forkchoiceResult2 engine.ForkChoiceResponse
	err = c.engineClient.CallContext(ctx, &forkchoiceResult2, "engine_forkchoiceUpdatedV3",
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

	fmt.Printf("tzdybal: %+v\n", forkchoiceResult2)

	if forkchoiceResult2.PayloadID == nil {
		return execution_types.Hash{}, 0, ErrNilPayloadStatus
	}

	c.payloadID = forkchoiceResult2.PayloadID

	const GENESIS_STATEROOT = "0x362b7d8a31e7671b0f357756221ac385790c25a27ab222dc8cbdd08944f5aea4"
	genesisStateRoot := common.HexToHash(GENESIS_STATEROOT)

	//txs, err := c.GetTxs(ctx)
	//if err != nil {
	//	return execution_types.Hash{}, 0, fmt.Errorf("failed to get genesis txs: %w", err)
	//}
	//_, _, err = c.ExecuteTxs(ctx, txs, initialHeight, genesisTime, c.genesisHash[:])
	//if err != nil {
	//	return execution_types.Hash{}, 0, fmt.Errorf("failed to execute genesis txs: %w", err)
	//}

	//var payloadResult engine.ExecutionPayloadEnvelope
	//err = c.engineClient.CallContext(ctx, &payloadResult, "engine_getPayloadV3", forkchoiceResult2.PayloadID)
	//if err != nil {
	//	return execution_types.Hash{}, 0, fmt.Errorf("engine_getPayloadV3 failed: %w", err)
	//}
	//stateRoot := payloadResult.ExecutionPayload.StateRoot
	//gasLimit := payloadResult.ExecutionPayload.GasLimit
	//fmt.Println("tzdybal:", payloadResult.ExecutionPayload.BlockHash.Hex())
	//fmt.Println("tzdybal:", c.genesisHash.Hex())

	//return stateRoot[:], gasLimit, nil
	return genesisStateRoot[:], 600000000, nil
}

func (c *PureEngineClient) GetTxs(ctx context.Context) ([]execution_types.Tx, error) {
	var payloadResult engine.ExecutionPayloadEnvelope
	err := c.engineClient.CallContext(ctx, &payloadResult, "engine_getPayloadV3", c.payloadID)
	if err != nil {
		return nil, fmt.Errorf("engine_getPayloadV3 failed: %w", err)
	}
	c.building = true

	jsonPayloadResult, err := json.Marshal(payloadResult)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize payloadResult: %w", err)
	}

	var newPayloadResult engine.ExecutionPayloadEnvelope
	err = json.Unmarshal(jsonPayloadResult, &newPayloadResult)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal payloadResult: %w", err)
	}

	jsonPayloadResult2, err := json.Marshal(payloadResult)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize payloadResult: %w", err)
	}
	if !bytes.Equal(jsonPayloadResult, jsonPayloadResult2) {
		return nil, fmt.Errorf("payloadResult has changed")
	}

	txs := make([]execution_types.Tx, len(payloadResult.ExecutionPayload.Transactions)+1)
	for i, tx := range payloadResult.ExecutionPayload.Transactions {
		txs[i] = tx
	}
	txs[len(txs)-1] = jsonPayloadResult

	return txs, nil
}

func (c *PureEngineClient) ExecuteTxs(ctx context.Context, txs []execution_types.Tx, blockHeight uint64, timestamp time.Time, prevStateRoot execution_types.Hash) (updatedStateRoot execution_types.Hash, maxBytes uint64, err error) {
	var payloadResult engine.ExecutionPayloadEnvelope
	lastTx := txs[len(txs)-1]
	err = json.Unmarshal(lastTx, &payloadResult)
	if err != nil {
		return execution_types.Hash{}, 0, fmt.Errorf("failed to deserialize last transaction as ExecutionPayload: %w", err)
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

	if newPayloadResult.Status == engine.INVALID {
		return execution_types.Hash{}, 0, fmt.Errorf("new payload submission failed with: %s", *newPayloadResult.ValidationError)
	}

	// forkchoice update
	blockHash := payloadResult.ExecutionPayload.BlockHash
	var forkchoiceResult engine.ForkChoiceResponse
	err = c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
		engine.ForkchoiceStateV1{
			HeadBlockHash:      blockHash,
			SafeBlockHash:      blockHash,
			FinalizedBlockHash: blockHash,
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

	// Pretty print the fork choice result
	fmt.Printf("Fork Choice Result: %+v\n", forkchoiceResult)

	if forkchoiceResult.PayloadStatus.Status == engine.INVALID {
		return nil, 0, ErrInvalidPayloadStatus
	}

	c.payloadID = forkchoiceResult.PayloadID

	return payloadResult.ExecutionPayload.StateRoot.Bytes(), payloadResult.ExecutionPayload.GasLimit, nil
}

func (c *PureEngineClient) SetFinal(ctx context.Context, blockHeight uint64) error {
	//TODO implement me
	panic("implement me")
}
func (c *PureEngineClient) setFinal(ctx context.Context, blockHash common.Hash) error {
	var forkchoiceResult engine.ForkChoiceResponse
	err := c.engineClient.CallContext(ctx, &forkchoiceResult, "engine_forkchoiceUpdatedV3",
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

	c.payloadID = forkchoiceResult.PayloadID

	return nil
}

func (c *PureEngineClient) derivePrevRandao(blockHeight uint64) common.Hash {
	return common.BigToHash(big.NewInt(int64(blockHeight))) //nolint:gosec // disable G115
}
