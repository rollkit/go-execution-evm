package commands

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	evm "github.com/rollkit/go-execution-evm"
	grpcproxy "github.com/rollkit/go-execution/proxy/grpc"
	pb "github.com/rollkit/go-execution/types/pb/execution"
)

var (
	jwtSecret      string
	listenAddress  string
	genesisHashHex string
	ethURL         string
	engineURL      string
	maxMsgSize     int
)

func init() {
	// Command-line flags for `run`
	runCmd.Flags().StringVar(&jwtSecret, "jwt-secret", "", "JWT secret for the Engine API connection")
	if err := runCmd.MarkFlagRequired("jwt-secret"); err != nil {
		log.Fatalf("Error marking flag 'jwt-secret' as required: %v", err)
	}
	runCmd.Flags().StringVar(&listenAddress, "listen-address", "0.0.0.0:40041", "Address to listen for gRPC connections")
	runCmd.Flags().StringVar(&genesisHashHex, "genesis-hash", "0x8bf225d50da44f60dee1c4ee6f810fe5b44723c76ac765654b6692d50459f216", "Genesis hash of the EVM chain")
	runCmd.Flags().StringVar(&ethURL, "eth-url", "http://127.0.0.1:8545", "URL of the ETH API exposed by EVM node")
	runCmd.Flags().StringVar(&engineURL, "engine-url", "http://127.0.0.1:8551", "URL of the Engine API exposed by EVM node")
	runCmd.Flags().IntVar(&maxMsgSize, "max-msg-size", 4*1024*1024, "Maximum message size for gRPC connections (in bytes)") // New flag for maxMsgSize

	// Attach the `runCmd` to the root command
	rootCmd.AddCommand(runCmd)
}

var runCmd = &cobra.Command{
	Use:     "run",
	Aliases: []string{"start", "node"},
	Short:   "Run the EVM middleware for Rollkit",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if _, err := hexutil.Decode(genesisHashHex); err != nil {
			return fmt.Errorf("invalid genesis hash format: %s, error: %w", genesisHashHex, err)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		listener, err := net.Listen("tcp", listenAddress)
		if err != nil {
			return fmt.Errorf("error while creating listener: %w\n", err)
		}
		defer func() {
			_ = listener.Close()
		}()

		genesisHash := common.HexToHash(genesisHashHex)

		evmClient, err := evm.NewEngineAPIExecutionClient(ethURL, engineURL, jwtSecret, genesisHash, common.Address{})
		if err != nil {
			return fmt.Errorf("failed to create Engine API client middleware: %w", err)
		}
		_ = evmClient.Start()
		defer evmClient.Stop()

		log.Println("Starting GRPC server...")
		server := grpcproxy.NewServer(evmClient, grpcproxy.DefaultConfig())
		s := grpc.NewServer(
			grpc.MaxRecvMsgSize(maxMsgSize), // Use the value from the flag
			grpc.MaxSendMsgSize(maxMsgSize), // Use the value from the flag
		)
		pb.RegisterExecutionServiceServer(s, server)

		wg := sync.WaitGroup{}
		wg.Add(1)

		go func() {
			log.Println("Serving go-execution API...")
			if err := s.Serve(listener); err != nil {
				if !errors.Is(err, grpc.ErrServerStopped) {
					log.Printf("Server exited with error: %v\n", err)
				}
				// Trigger graceful shutdown
				s.GracefulStop()
			}
			wg.Done()
		}()
		defer s.Stop()

		wg.Wait()
		log.Println("Server stopped")
		return nil
	},
}
