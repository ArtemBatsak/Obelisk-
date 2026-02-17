Server Data & Manager Utils

Utilities for storing server metadata and managing active GrayServer instances.

Persistent server registry (file-backed)

Random unique server IDs

Automatic port allocation

Thread-safe access

Runtime server lifecycle management

Components

Server_struct — server ID, ports, comment (simple serialization)

DataServers — manages known servers and free ports

ServerManager — tracks active servers, supports remove/shutdown

Notes

Uses text files (Servers.txt, Port.txt).
Intended for internal / controlled environments.