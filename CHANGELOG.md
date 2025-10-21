# [1.1.0.1] - 2025-10-21

- Update slick_queue to v1.1.0.2
- Change namespace from slick_net to slick::net
- Change include folder structure from include/slick_net to include/slick/net

# [1.1.0.0] - 2025-10-19

- Added plain WebSocket (ws://) and plain Http (http://) protocol support
- Added Comprehensive test coverage for plain HTTP (non-SSL) client

## [1.0.0] - 2025-10-11

- Initial release of slick_net
- HTTP/HTTPS client with full SSL/TLS support
  - Synchronous methods: GET, POST, PUT, PATCH, DELETE
  - Asynchronous methods with callback-based API
  - Custom header support
- WebSocket/WebSocket Secure (WSS) client
  - Built on Boost.Beast and Boost.Asio coroutines
  - Full SSL/TLS support for wss:// connections
  - Non-SSL support for ws:// connections
  - Event-driven callback API (onConnected, onDisconnected, onData, onError)
  - Binary and text message support
  - Thread-safe concurrent operations
- HTTP Streaming support (HttpStream)
  - Server-Sent Events (SSE) support
  - Chunked response streaming
  - Custom header support
- Comprehensive test suite using Google Test
  - HTTP client tests (sync and async)
  - WebSocket client tests (connection lifecycle, messaging, error handling)
  - HTTP streaming tests
- Example applications
  - websocket_client_example
  - http_client_example
  - http_stream_client_example