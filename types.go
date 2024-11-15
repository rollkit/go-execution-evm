package execution

import (
	"github.com/ethereum/go-ethereum/common"
)

type PayloadStatus string

const (
	PayloadStatusValid   PayloadStatus = "VALID"
	PayloadStatusInvalid PayloadStatus = "INVALID"
	PayloadStatusSyncing PayloadStatus = "SYNCING"
)

// ForkchoiceUpdatedResponse represents the response from engine_forkchoiceUpdatedV3
type ForkchoiceUpdatedResponse struct {
	PayloadStatus struct {
		Status          PayloadStatus `json:"status"`
		ValidationError *string       `json:"validationError,omitempty"`
	} `json:"payloadStatus"`
	PayloadID *string `json:"payloadId,omitempty"`
}

// ExecutionPayload represents the payload data from the execution client
type ExecutionPayload struct {
	StateRoot string `json:"stateRoot"`
	GasUsed   string `json:"gasUsed"`
	GasLimit  string `json:"gasLimit"`
}

// PayloadResponse represents the response from engine_getPayloadV3
type PayloadResponse struct {
	ExecutionPayload ExecutionPayload `json:"executionPayload"`
}

// ForkchoiceState represents the forkchoice state for engine API calls
type ForkchoiceState struct {
	HeadBlockHash      common.Hash `json:"headBlockHash"`
	SafeBlockHash      common.Hash `json:"safeBlockHash"`
	FinalizedBlockHash common.Hash `json:"finalizedBlockHash"`
}

// PayloadAttributes represents the payload attributes for engine API calls
type PayloadAttributes struct {
	Timestamp             int64          `json:"timestamp"`
	PrevRandao            common.Hash    `json:"prevRandao"`
	SuggestedFeeRecipient common.Address `json:"suggestedFeeRecipient"`
	ParentBeaconBlockRoot common.Hash    `json:"parentBeaconBlockRoot"`
}

// NewPayloadRequest represents the request parameters for engine_newPayloadV3
type NewPayloadRequest struct {
	ParentHash                  common.Hash    `json:"parentHash"`
	Timestamp                   int64          `json:"timestamp"`
	PrevRandao                  common.Hash    `json:"prevRandao"`
	FeeRecipient                common.Address `json:"feeRecipient"`
	Transactions                [][]byte       `json:"transactions"`
	ExpectedBlobVersionedHashes []string       `json:"expectedBlobVersionedHashes"`
	ParentBeaconBlockRoot       common.Hash    `json:"parentBeaconBlockRoot"`
}
