# slick_net

A high-performance C++ WebSocket client library built on Boost.Beast with full SSL/TLS support. Designed for asynchronous, non-blocking WebSocket communication in modern C++ applications.

## Features

- **Asynchronous WebSocket Client**: Built on Boost.Asio coroutines for high-performance async operations
- **SSL/TLS Support**: Native support for secure `wss://` connections
- **Cross-Platform**: Works on Windows, Linux, and macOS
- **Header-Only**: Easy integration with minimal dependencies
- **Callback-Based API**: Clean event-driven interface for connection lifecycle management
- **Thread-Safe**: Proper strand management for concurrent operations
- **Modern C++20**: Leverages coroutines and modern C++ features

## Dependencies

- **Boost** (1.75+): beast, asio, context components
- **OpenSSL**: For SSL/TLS support
- **C++20 Compiler**: Required for coroutine support

## Installation

### CMake Integration

Add slick_net as a subdirectory in your CMake project:

```cmake
add_subdirectory(path/to/slick_net)
target_link_libraries(your_target PRIVATE slick_net)
```

Or use FetchContent:

```cmake
include(FetchContent)
FetchContent_Declare(
    slick_net
    GIT_REPOSITORY https://github.com/SlickQuant/slick_net.git
    GIT_TAG main
)
FetchContent_MakeAvailable(slick_net)
target_link_libraries(your_target PRIVATE slick_net)
```

## Usage

### Basic WebSocket Client

```cpp
#include <slick_net/websocket.h>
#include <memory>

using namespace slick_net;

int main() {
    auto ws = std::make_shared<Websocket>(
        "wss://echo.websocket.org",           // WebSocket URL
        []() {                                // onConnected
            std::cout << "Connected!\n";
        },
        []() {                                // onDisconnected
            std::cout << "Disconnected!\n";
        },
        [](const char* data, size_t size) {   // onData
            std::cout << "Received: " << std::string(data, size) << "\n";
        },
        [](std::string err) {                 // onError
            std::cerr << "Error: " << err << "\n";
        }
    );
    
    ws->open();
    
    // Send a message
    std::string message = "Hello, WebSocket!";
    ws->send(message.data(), message.size());
    
    // Keep the application running
    while(Websocket::is_running()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return 0;
}
```

### Advanced Usage with JSON

```cpp
#include <slick_net/websocket.h>
#include <nlohmann/json.hpp>
#include <memory>

using namespace slick_net;
using json = nlohmann::json;

int main() {
    auto ws = std::make_shared<Websocket>(
        "wss://advanced-trade-ws.coinbase.com",
        [&ws]() { 
            std::cout << "Connected to Coinbase\n";
            // Subscribe to market data
            json subscribe_msg = {
                {"type", "subscribe"},
                {"channel", "level2"},
                {"product_ids", {"BTC-USD"}}
            };
            auto msg_str = subscribe_msg.dump();
            ws->send(msg_str.data(), msg_str.size());
        },
        []() {
            std::cout << "Disconnected from Coinbase\n";
        },
        [](const char* data, size_t size) {
            std::cout << "Market data: " << std::string(data, size) << "\n";
        },
        [](std::string err) {
            std::cerr << "Error: " << err << "\n";
        }
    );
    
    ws->open();
    
    // Keep running
    while(Websocket::is_running()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    return 0;
}
```

## Build Examples

The repository includes working examples. To build them:

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

Run the WebSocket client example:
```bash
./examples/websocket_client_example
```

## API Reference

### Websocket Class

**Constructor:**
```cpp
Websocket(
    std::string url,
    std::function<void()> onConnected,
    std::function<void()> onDisconnected,
    std::function<void(const char*, std::size_t)> onData,
    std::function<void(std::string)> onError
)
```

**Methods:**
- `void open()` - Start the WebSocket connection
- `void close()` - Close the WebSocket connection
- `void send(const char* buffer, size_t len)` - Send data through the WebSocket
- `Status status() const` - Get current connection status
- `static void shutdown()` - Shutdown all WebSocket services

**Status Enum:**
- `CONNECTING` - Connection in progress
- `CONNECTED` - Connected and ready
- `DISCONNECTING` - Disconnection in progress
- `DISCONNECTED` - Disconnected

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Part of the [SlickQuant](https://github.com/SlickQuant) ecosystem.
