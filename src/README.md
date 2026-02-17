Main Program Flow

Initializes asio::io_context for asynchronous operations.

Loads server metadata via DataServers.

Creates a ServerManager to hold and manage active GrayServer instances.

Sets up signal handling for cross-platform graceful shutdown (Ctrl+C / SIGTERM).

Configures TLS context using a self-signed certificate generated at runtime.

Starts listening on the control port (44555) for TLS-authenticated servers.

Launches a thread pool to run io_context.

Launches a command thread to manage servers interactively.

asio::io_context io;
DataServers data_servers;
auto server_manager = std::make_shared<ServerManager>();

Control Connections

TLS-enabled control connections are accepted on a dedicated control port.

Each new connection is handled by start_control_accept().

Accepts sockets asynchronously using async_accept().

After each accepted connection, it immediately prepares the next accept call for continuous operation.

Authorization and GrayServer Creation

TLS handshake is performed asynchronously via async_handshake().

After handshake, the client sends its server ID for authorization.

The server checks the ID against DataServers::authorize_id().

If authorized, the server sends an acknowledgment (OK).

Client also sends a pool size indicating how many sockets to maintain for concurrent clients.

GrayServer instance is created via std::make_shared and initialized:

auto server = std::make_shared<GrayServer>(
    id,
    self,
    io,
    ports.client_port,
    ports.data_port,
    pool_size,
    server_manager
);


GrayServer is added to ServerManager and started immediately (server->start()).

Ports assigned for the new server are sent back to the client.

Note: Passing the ServerManager allows the GrayServer to self-remove when shutdown occurs, ensuring safe lifecycle management.

Threading Model

io_context runs on a thread pool equal to the hardware concurrency for asynchronous scalability.

Each thread calls io.run() to process asynchronous events.

The command thread is separate and synchronous; it interacts with DataServers and can trigger server shutdowns.

Command Thread

Interactive command loop for managing servers and IDs:

/add      - Add a new server ID and assign ports
/show     - Show all registered servers
/delete   - Delete a server ID and release ports
/shutdown - Stop all servers and exit


Commands are read from standard input.

All operations are safe and synchronized with server state.

Shutdown Handling

Signal handlers for SIGINT (Ctrl+C) and SIGTERM invoke graceful shutdown.

ServerManager::shutdown_all() closes all active GrayServers.

io_context::stop() stops all asynchronous operations.

Ensures all sockets, timers, and acceptors are closed before exit.