## Architecture

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
            ProxyClient[JSON-RPC Proxy Client]
        end
    end

    subgraph Proxy Layer
        ProxyServer[JSON-RPC Proxy Server]
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
    ProxyServer -->|delegates to| MockExecutor

    %% Execution Client Connections
    EngineAPIExecutionClient -->|eth calls| EthClient
    EngineAPIExecutionClient -->|engine calls| ProxyClient
    EthClient -->|eth/net/web3| JsonRPC
    ProxyClient -->|forwards requests| ProxyServer

    %% Proxy to Reth Connections
    ProxyServer -->|authenticated requests| EngineAPI
    JsonRPC -->|internal| Reth
    EngineAPI -->|internal| Reth

    %% Styling
    classDef primary fill:#f9f,stroke:#333,stroke-width:2px
    classDef secondary fill:#bbf,stroke:#333,stroke-width:1px
    class EngineAPIExecutionClient,ProxyServer primary
    class EthClient,ProxyClient,MockExecutor,EngineAPI,JsonRPC secondary
```

The architecture consists of several key components:

1. **Execution Client**

   - `EngineAPIExecutionClient`: Main client interface
   - `EthClient`: Handles standard Ethereum JSON-RPC calls
   - `ProxyClient`: Handles Engine API calls through the proxy

2. **Proxy Layer**

   - `JSON-RPC Proxy Server`: Authenticates and forwards Engine API requests
   - Handles JWT authentication with Reth

3. **Execution Layer**

   - `Reth Node`: Ethereum execution client
   - Exposes Engine API and standard JSON-RPC endpoints

4. **Test Environment**
   - `Test Client`: Integration tests
   - `Mock Executor`: Simulates execution behavior for unit tests

## Development

```bash
$ cd docker
$ docker compose up -d
$ docker compose down
```
