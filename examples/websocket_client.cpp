#include <slick_logger/logger.hpp>  // must be included before <slick_net/websocket.h>
#include <slick_net/websocket.h>
#include <thread>
#include <nlohmann/json.hpp>
using namespace slick_net;
using namespace slick_logger;

// slick_logger defines LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_TRACE macros

// User can assign their own log functions by defining these macros before including <slick_net/websocket.h>
// The log functions must support fmt-style formatting
// e.g. LOG_INFO("Hello {}", "world");

int main()
{
    auto &logger = Logger::instance();
    logger.add_console_sink(true, true);
    logger.set_level(LogLevel::L_INFO);
    logger.init(1024); // use pre-added sinks

    std::shared_ptr<slick_net::Websocket> ws;
    ws = std::make_shared<slick_net::Websocket>(
        // "wss://echo.websocket.org",
        "wss://advanced-trade-ws.coinbase.com",
        [&ws](){ 
            LOG_INFO("ws connected");
            nlohmann::json req = R"({
                "type": "subscribe",
                "channel": "level2",
                "product_ids": ["BTC-USD"]
            })"_json;
            auto str_req = req.dump();
            ws->send(str_req.data(), str_req.size()); 
        },                                                                                          // onConnected
        [](){ LOG_INFO("ws disconnected"); },                                                       // onDisconnected
        [&ws](const char* data, size_t size){ LOG_INFO("onData: {}", std::string(data, size)); },   // onData
        [&ws](std::string err){ LOG_ERROR("onError: {}", std::move(err)); ws->close(); }            // onError
    );
    ws->open();

    // Ctrl-C to exit

    while(Websocket::is_running())
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}