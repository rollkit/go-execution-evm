# Architecture

```mermaid
graph LR
    subgraph Test Environment
        TestClient[Test Client]
        MockExecutor[Mock Executor]
    end

    subgraph Execution Client
        EngineAPIExecutionClient
        subgraph Client Components
            EthClient[Eth Client]
            JsonRpcClient[JSON-RPC Client]
        end
    end

    subgraph Execution Layer
        Reth[Reth Node]
        subgraph Reth APIs
            EngineAPI[Engine API]
            JsonRPC[JSON-RPC API]
        end
    end

    %% Test Environment Connections
    TestClient -->|uses| EngineAPIExecutionClient
    JsonRpcClient -->|test mode| MockExecutor

    %% Execution Client Connections
    EngineAPIExecutionClient -->|eth calls| EthClient
    EngineAPIExecutionClient -->|engine calls| JsonRpcClient
    EthClient -->|eth/net/web3| JsonRPC
    JsonRpcClient -->|engine api| EngineAPI

    %% Reth Internal Connections
    JsonRPC -->|internal| Reth
    EngineAPI -->|internal| Reth

    %% Styling
    classDef primary fill:#f9f,stroke:#333,stroke-width:2px
    classDef secondary fill:#bbf,stroke:#333,stroke-width:1px
    class EngineAPIExecutionClient primary
    class EthClient,JsonRpcClient,MockExecutor,EngineAPI,JsonRPC secondary
```

The architecture consists of several key components:

1. **Execution Client**

   - `EngineAPIExecutionClient`: Main client interface that implements the Execute interface
   - `EthClient`: Handles standard Ethereum JSON-RPC calls
   - `JsonRpcClient`: Handles Engine API calls

2. **Execution Layer**

   - `Reth Node`: Ethereum execution client
   - Exposes Engine API and standard JSON-RPC endpoints

3. **Test Environment**
   - `Test Client`: Integration tests
   - `Mock Executor`: Simulates execution behavior for unit tests

## Development

Run RETH in docker:

```bash
cd docker
docker compose up -d
```

Compile `evm-middleware` binary:

```bash
make build
```

Run `evm-middleware` binary:

```bash
./build/evm-middleware run --jwt-secret $(cat docker/jwttoken/jwt.hex)
```

Compile rollkit from `feature/exec_api` branch and run it:

```bash
git checkout feature/exec_api
go build ./cmd/rollkit
./rollkit start
```
