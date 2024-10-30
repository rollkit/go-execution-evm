package execution

import (
	"time"

	execution "github.com/rollkit/go-execution"
	rollkitTypes "github.com/rollkit/rollkit/types"
)

type EngineAPIExecutionClient struct {
	execute execution.Execute
}

// NewEngineAPIExecutionClient creates a new instance of EngineAPIExecutionClient.
func NewEngineAPIExecutionClient(execute execution.Execute) (*EngineAPIExecutionClient, error) {
	return &EngineAPIExecutionClient{
		execute: execute,
	}, nil
}

var _ execution.Execute = (*EngineAPIExecutionClient)(nil)

// InitChain initializes the blockchain with genesis information.
func (c *EngineAPIExecutionClient) InitChain(
	genesisTime time.Time,
	initialHeight uint64,
	chainID string,
) (rollkitTypes.Hash, uint64, error) {
	return c.execute.InitChain(genesisTime, initialHeight, chainID)
}

// GetTxs retrieves transactions from the transaction pool.
func (c *EngineAPIExecutionClient) GetTxs() ([]rollkitTypes.Tx, error) {
	return c.execute.GetTxs()
}

// ExecuteTxs executes the given transactions and returns the new state root and gas used.
func (c *EngineAPIExecutionClient) ExecuteTxs(
	txs []rollkitTypes.Tx,
	blockHeight uint64,
	timestamp time.Time,
	prevStateRoot rollkitTypes.Hash,
) (rollkitTypes.Hash, uint64, error) {
	return c.execute.ExecuteTxs(txs, blockHeight, timestamp, prevStateRoot)
}

// SetFinal marks a block at the given height as final.
func (c *EngineAPIExecutionClient) SetFinal(blockHeight uint64) error {
	return c.execute.SetFinal(blockHeight)
}
