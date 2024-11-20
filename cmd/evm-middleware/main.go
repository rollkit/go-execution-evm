package main

import (
	"errors"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"

	evm "github.com/rollkit/go-execution-evm"
	grpcproxy "github.com/rollkit/go-execution/proxy/grpc"
	pb "github.com/rollkit/go-execution/types/pb/execution"
)

const bufSize = 1024 * 1024

func main() {
	jwtSecret := ""
	if len(os.Args) == 2 {
		jwtSecret = os.Args[1]
	}

	config := &grpcproxy.Config{
		DefaultTimeout: 5 * time.Second,
		MaxRequestSize: bufSize,
	}

	listener, err := net.Listen("tcp4", "0.0.0.0:40041") //nolint:gosec
	if err != nil {
		log.Fatalf("error while creating listener: %v\n", err)
	}
	defer func() {
		_ = listener.Close()
	}()

	// TODO(tzdybal): initialize from genesis file?
	var genesisHash common.Hash
	var feeRecipient common.Address

	genesis := core.DefaultGenesisBlock()
	genesisHash = genesis.ToBlock().Hash()

	evmClient, err := evm.NewEngineAPIExecutionClient("http://:8545", "http://8551", jwtSecret, genesisHash, feeRecipient)
	if err != nil {
		log.Fatalf("failed to create Engine API client middleware: %v", err)
	}
	_ = evmClient.Start()
	defer evmClient.Stop()

	log.Println("Starting server...")
	server := grpcproxy.NewServer(evmClient, config)
	s := grpc.NewServer()
	pb.RegisterExecutionServiceServer(s, server)

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		log.Println("Serving...")
		if err := s.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			log.Fatalf("Server exited with error: %v\n", err)
		}
		wg.Done()
	}()
	defer s.Stop()

	wg.Wait()
	log.Println("Server stopped")
}
