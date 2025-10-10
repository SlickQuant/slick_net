# slick_net

A high-performance C++ HTTP/WebSocket client library built on Boost.Beast with full SSL/TLS support. Designed for asynchronous, non-blocking HTTP/WebSocket communication in modern C++ applications.

## Features

- **HTTP/HTTPS Client**: Full support for GET, POST, PUT, PATCH, and DELETE methods
- **HTTP Streaming**: Support for Server-Sent Events (SSE) and chunked response streaming
- **Asynchronous WebSocket Client**: Built on Boost.Asio coroutines for high-performance async operations
- **SSL/TLS Support**: Native support for secure `https://` and `wss://` connections
- **Synchronous & Asynchronous APIs**: Both blocking and non-blocking HTTP operations
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
        "wss://ws.postman-echo.com/raw",           // WebSocket URL
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

Run examples:
```bash
./examples/websocket_client_example
./examples/http_client_example
./examples/http_stream_client_example
```

## API Reference

### Http Class

**Synchronous Methods:**
```cpp
Http::Response get(std::string_view url, std::vector<std::pair<std::string, std::string>>&& headers = {});
Http::Response post(std::string_view url, std::string_view data, std::vector<std::pair<std::string, std::string>>&& headers = {});
Http::Response put(std::string_view url, std::string_view data, std::vector<std::pair<std::string, std::string>>&& headers = {});
Http::Response patch(std::string_view url, std::string_view data, std::vector<std::pair<std::string, std::string>>&& headers = {});
Http::Response del(std::string_view url, std::string_view data, std::vector<std::pair<std::string, std::string>>&& headers = {});
```

**Asynchronous Methods:**
```cpp
void async_get(std::function<void(Response&&)> on_response, std::string_view url, std::vector<std::pair<std::string, std::string>>&& headers = {});
void async_post(std::function<void(Response&&)> on_response, std::string_view url, std::string_view data, std::vector<std::pair<std::string, std::string>>&& headers = {});
void async_put(std::function<void(Response&&)> on_response, std::string_view url, std::string_view data, std::vector<std::pair<std::string, std::string>>&& headers = {});
void async_patch(std::function<void(Response&&)> on_response, std::string_view url, std::string_view data, std::vector<std::pair<std::string, std::string>>&& headers = {});
void async_del(std::function<void(Response&&)> on_response, std::string_view url, std::string_view data, std::vector<std::pair<std::string, std::string>>&& headers = {});
```

**Response Structure:**
```cpp
struct Response {
    uint32_t result_code;     // HTTP status code
    std::string result_text;  // Response body or error message
    bool is_ok() const;       // Returns true if status code is 2xx
};
```

**Example Usage:**
```cpp
#include <slick_net/http.h>

// Synchronous GET
auto response = Http::get("https://api.example.com/data");
if (response.is_ok()) {
    std::cout << response.result_text << std::endl;
}

// Asynchronous POST with JSON
nlohmann::json data = {{"key", "value"}};
Http::async_post([](Http::Response&& rsp) {
    if (rsp.is_ok()) {
        std::cout << "Success: " << rsp.result_text << std::endl;
    }
}, "https://api.example.com/resource", data.dump(), {{"Content-Type", "application/json"}});
```

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

### HttpStream Class

The `HttpStream` class provides support for HTTP streaming, including Server-Sent Events (SSE) and chunked responses.

**Constructor:**
```cpp
HttpStream(
    std::string url,
    std::function<void()> onConnected,
    std::function<void()> onDisconnected,
    std::function<void(const char*, std::size_t)> onData,
    std::function<void(std::string)> onError,
    std::vector<std::pair<std::string, std::string>>&& headers = {}
)
```

**Methods:**
- `void open()` - Start the HTTP stream connection
- `void close()` - Close the stream connection
- `Status status() const` - Get current connection status
- `static bool is_running()` - Check if any streams are running
- `static void shutdown()` - Shutdown all HTTP stream services

**Status Enum:**
- `CONNECTING` - Connection in progress
- `CONNECTED` - Connected and receiving data
- `DISCONNECTED` - Disconnected

**Example Usage - Server-Sent Events (SSE):**
```cpp
#include <slick_net/http.h>

auto stream = std::make_shared<HttpStream>(
    "https://api.example.com/events",
    []() {
        std::cout << "Stream connected\n";
    },
    []() {
        std::cout << "Stream disconnected\n";
    },
    [](const char* data, size_t size) {
        std::string event(data, size);
        std::cout << "Event: " << event << "\n";
    },
    [](std::string err) {
        std::cerr << "Error: " << err << "\n";
    }
);

stream->open();

// Stream will receive events via the onData callback
// Close when done
stream->close();
```

**Example Usage - OpenAI Streaming API:**
```cpp
#include <slick_net/http.h>
#include <nlohmann/json.hpp>

auto stream = std::make_shared<HttpStream>(
    "https://api.openai.com/v1/chat/completions",
    []() {
        std::cout << "Connected to OpenAI\n";
    },
    []() {
        std::cout << "Stream ended\n";
    },
    [](const char* data, size_t size) {
        // Parse streaming JSON chunks
        std::string chunk(data, size);
        try {
            auto json = nlohmann::json::parse(chunk);
            if (json.contains("choices")) {
                auto delta = json["choices"][0]["delta"];
                if (delta.contains("content")) {
                    std::cout << delta["content"].get<std::string>();
                }
            }
        } catch (...) {}
    },
    [](std::string err) {
        std::cerr << "Error: " << err << "\n";
    },
    {
        {"Authorization", "Bearer YOUR_API_KEY"},
        {"Content-Type", "application/json"}
    }
);

stream->open();
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Part of the [SlickQuant](https://github.com/SlickQuant) ecosystem.
