package execution

import (
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	execution "github.com/rollkit/go-execution"
	"github.com/rollkit/go-execution/proxy/jsonrpc"
	rollkitTypes "github.com/rollkit/rollkit/types"
)

// Define necessary types and constants
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

type EngineAPIExecutionClient struct {
	ethClient    *ethclient.Client
	proxyClient  *jsonrpc.Client
	genesisHash  common.Hash
	feeRecipient common.Address
}

// NewEngineAPIExecutionClient creates a new instance of EngineAPIExecutionClient.
func NewEngineAPIExecutionClient(ethURL string, proxyClient *jsonrpc.Client, genesisHash common.Hash, feeRecipient common.Address) (*EngineAPIExecutionClient, error) {
	ethClient, err := ethclient.Dial(ethURL)
	if err != nil {
		return nil, err
	}

	return &EngineAPIExecutionClient{
		ethClient:    ethClient,
		proxyClient:  proxyClient,
		genesisHash:  genesisHash,
		feeRecipient: feeRecipient,
	}, nil
}

var _ execution.Execute = (*EngineAPIExecutionClient)(nil)

// InitChain initializes the blockchain with genesis information.
func (c *EngineAPIExecutionClient) InitChain(
	genesisTime time.Time,
	initialHeight uint64,
	chainID string,
) (rollkitTypes.Hash, uint64, error) {
	return c.proxyClient.InitChain(genesisTime, initialHeight, chainID)
}

// GetTxs retrieves transactions from the transaction pool.
func (c *EngineAPIExecutionClient) GetTxs() ([]rollkitTypes.Tx, error) {
	return c.proxyClient.GetTxs()
}

// ExecuteTxs executes the given transactions and returns the new state root and gas used.
func (c *EngineAPIExecutionClient) ExecuteTxs(
	txs []rollkitTypes.Tx,
	blockHeight uint64,
	timestamp time.Time,
	prevStateRoot rollkitTypes.Hash,
) (rollkitTypes.Hash, uint64, error) {
	return c.proxyClient.ExecuteTxs(txs, blockHeight, timestamp, prevStateRoot)
}

// SetFinal marks a block at the given height as final.
func (c *EngineAPIExecutionClient) SetFinal(blockHeight uint64) error {
	return c.proxyClient.SetFinal(blockHeight)
}
