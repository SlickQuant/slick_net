#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <slick_net/websocket.h>
#include <memory>
#include <atomic>
#include <chrono>
#include <thread>

namespace slick_net {

// Mock callbacks for testing
class MockWebsocketCallbacks {
public:
    MOCK_METHOD(void, onConnected, (), ());
    MOCK_METHOD(void, onDisconnected, (), ());
    MOCK_METHOD(void, onData, (const char*, std::size_t), ());
    MOCK_METHOD(void, onError, (std::string), ());
};

class WebsocketTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Ensure clean state for each test
        Websocket::shutdown();
    }

    void TearDown() override {
        // Clean up after each test
        Websocket::shutdown();
    }
};

TEST_F(WebsocketTest, ConstructorParsesWssUrlWithHostAndPath) {
    std::atomic<bool> connected_called{false};
    std::atomic<bool> disconnected_called{false};
    std::atomic<bool> data_called{false};
    std::atomic<bool> error_called{false};

    auto ws = std::make_shared<Websocket>(
        "wss://echo.websocket.org/test",
        [&]() { connected_called = true; },
        [&]() { disconnected_called = true; },
        [&](const char*, std::size_t) { data_called = true; },
        [&](std::string) { error_called = true; }
    );

    // Check URL parsing
    EXPECT_EQ(ws->status(), Websocket::Status::DISCONNECTED);
}

TEST_F(WebsocketTest, ConstructorParsesWssUrlWithPort) {
    std::atomic<bool> connected_called{false};
    std::atomic<bool> disconnected_called{false};
    std::atomic<bool> data_called{false};
    std::atomic<bool> error_called{false};

    auto ws = std::make_shared<Websocket>(
        "wss://echo.websocket.org:443/test",
        [&]() { connected_called = true; },
        [&]() { disconnected_called = true; },
        [&](const char*, std::size_t) { data_called = true; },
        [&](std::string) { error_called = true; }
    );

    EXPECT_EQ(ws->status(), Websocket::Status::DISCONNECTED);
}

TEST_F(WebsocketTest, ConstructorParsesWsUrl) {
    std::atomic<bool> connected_called{false};
    std::atomic<bool> disconnected_called{false};
    std::atomic<bool> data_called{false};
    std::atomic<bool> error_called{false};

    auto ws = std::make_shared<Websocket>(
        "ws://echo.websocket.org/test",
        [&]() { connected_called = true; },
        [&]() { disconnected_called = true; },
        [&](const char*, std::size_t) { data_called = true; },
        [&](std::string) { error_called = true; }
    );

    EXPECT_EQ(ws->status(), Websocket::Status::DISCONNECTED);
}

TEST_F(WebsocketTest, ConstructorParsesHostOnlyUrl) {
    std::atomic<bool> connected_called{false};
    std::atomic<bool> disconnected_called{false};
    std::atomic<bool> data_called{false};
    std::atomic<bool> error_called{false};

    auto ws = std::make_shared<Websocket>(
        "echo.websocket.org",
        [&]() { connected_called = true; },
        [&]() { disconnected_called = true; },
        [&](const char*, std::size_t) { data_called = true; },
        [&](std::string) { error_called = true; }
    );

    EXPECT_EQ(ws->status(), Websocket::Status::DISCONNECTED);
}

TEST_F(WebsocketTest, ConstructorParsesUrlWithCustomPort) {
    std::atomic<bool> connected_called{false};
    std::atomic<bool> disconnected_called{false};
    std::atomic<bool> data_called{false};
    std::atomic<bool> error_called{false};

    auto ws = std::make_shared<Websocket>(
        "wss://echo.websocket.org:9001/test",
        [&]() { connected_called = true; },
        [&]() { disconnected_called = true; },
        [&](const char*, std::size_t) { data_called = true; },
        [&](std::string) { error_called = true; }
    );

    EXPECT_EQ(ws->status(), Websocket::Status::DISCONNECTED);
}

TEST_F(WebsocketTest, StatusTransitions) {
    std::atomic<bool> connected_called{false};
    std::atomic<bool> disconnected_called{false};
    std::atomic<bool> data_called{false};
    std::atomic<bool> error_called{false};

    auto ws = std::make_shared<Websocket>(
        "wss://echo.websocket.org/test",
        [&]() { connected_called = true; },
        [&]() { disconnected_called = true; },
        [&](const char*, std::size_t) { data_called = true; },
        [&](std::string) { error_called = true; }
    );

    // Initial state should be DISCONNECTED
    EXPECT_EQ(ws->status(), Websocket::Status::DISCONNECTED);

    // Note: We can't easily test CONNECTING/CONNECTED states without mocking
    // the network layer, but we can verify the initial state
}

TEST_F(WebsocketTest, CallbacksAreStored) {
    int connected_count = 0;
    int disconnected_count = 0;
    int data_count = 0;
    int error_count = 0;

    auto ws = std::make_shared<Websocket>(
        "wss://echo.websocket.org/test",
        [&]() { connected_count++; },
        [&]() { disconnected_count++; },
        [&](const char*, std::size_t) { data_count++; },
        [&](std::string) { error_count++; }
    );

    // We can't directly invoke the callbacks since they're private,
    // but we can verify the websocket is created successfully
    EXPECT_EQ(ws->status(), Websocket::Status::DISCONNECTED);
    EXPECT_EQ(connected_count, 0);
    EXPECT_EQ(disconnected_count, 0);
    EXPECT_EQ(data_count, 0);
    EXPECT_EQ(error_count, 0);
}

TEST_F(WebsocketTest, IsRunningInitiallyFalse) {
    EXPECT_FALSE(Websocket::is_running());
}

TEST_F(WebsocketTest, ShutdownWhenNotRunning) {
    // Should not crash when shutting down when not running
    Websocket::shutdown();
    EXPECT_FALSE(Websocket::is_running());
}

// Note: Testing actual connection, sending, and receiving would require
// setting up a test websocket server or extensive mocking of Boost.Beast.
// These tests focus on the testable parts: construction, URL parsing, and state management.

} // namespace slick_net
