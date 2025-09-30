// The MIT License (MIT)
// Copyright (c) 2025 SlickQuant
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include "pch.h"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace websocket = beast::websocket; // from <boost/beast/websocket.hpp>
namespace asio = boost::asio;           // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl;       // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

// Logging function placeholders
// User can assign their own log functions by defining these macros before including this file
// The log functions must support fmt-style formatting e.g. LOG_INFO("Hello {}", "world");

#ifndef LOG_DEBUG
#define LOG_DEBUG(...) do {} while(0)
#endif
#ifndef LOG_INFO  
#define LOG_INFO(...) do {} while(0)
#endif
#ifndef LOG_WARN
#define LOG_WARN(...) do {} while(0)
#endif
#ifndef LOG_ERROR
#define LOG_ERROR(...) do {} while(0)
#endif
#ifndef LOG_TRACE
#define LOG_TRACE(...) do {} while(0)
#endif

namespace slick_net {

class Websocket : public std::enable_shared_from_this<Websocket>
{   
public:
    explicit Websocket(
        std::string url,
        std::function<void()> &&onConnectedCallback,
        std::function<void()> &&onDiconnectedCallback,
        std::function<void(const char*, std::size_t)> &&onDataCallback,
        std::function<void(std::string err)> &&onErrorCallback
    );

    ~Websocket() = default;

    // Start the asynchronous operation
    void open();

    void close();

    void send(const char* buffer, size_t len);

    static void shutdown();

    enum class Status : uint8_t 
    {
        CONNECTING,
        CONNECTED,
        DISCONNECTING,
        DISCONNECTED,
    };

    Status status() const noexcept
    {
        return status_.load(std::memory_order_relaxed);
    }

    static bool is_running() noexcept
    {
        return run_.load(std::memory_order_relaxed);
    }

private:
    asio::awaitable<void> do_wss_session();
    void do_write();
    void on_write(beast::error_code ec, std::size_t bytes_transferred);
    void on_read(beast::error_code ec, std::size_t bytes_transferred);
    void on_close(beast::error_code ec);

private:
    static asio::io_context ioc_;
    static ssl::context ctx_;
    static std::thread service_thread_;
    static std::atomic_int_fast32_t next_id_;
    static std::atomic_bool init_service_thread_;
    static std::atomic_bool run_;
    static std::unordered_map<std::string, std::shared_ptr<Websocket>> sockets_;

    websocket::stream<ssl::stream<beast::tcp_stream>> ws_;
    beast::flat_buffer r_buffer_;
    std::string url_;
    std::string host_;
    std::string path_;
    uint_fast16_t port_ = -1;
    std::function<void()> on_connected_;
    std::function<void()> on_diconnected_;
    std::function<void(const char*, std::size_t)> on_data_;
    std::function<void(std::string err)> on_error_;
    std::atomic<Status> status_{ Status::DISCONNECTED };
    slick::SlickQueue<char> w_buffer_;
    uint64_t w_cursor_{0};
    std::atomic_bool in_writting_{false};
};

// ---------------------------------------------------- Implementation ----------------------------------------------------

// Static member definitions
inline asio::io_context Websocket::ioc_;
inline ssl::context Websocket::ctx_{ssl::context::tlsv12_client};
inline std::atomic_int_fast32_t Websocket::next_id_ = 0;
inline std::thread Websocket::service_thread_;
inline std::atomic_bool Websocket::init_service_thread_{ false };
inline std::atomic_bool Websocket::run_;

inline Websocket::Websocket(
    std::string url,
    std::function<void()> &&onConnectedCallback,
    std::function<void()> &&onDiconnectedCallback,
    std::function<void(const char*, std::size_t)> &&onDataCallback,
    std::function<void(std::string err)> &&onErrorCallback)
    : ws_(asio::make_strand(Websocket::ioc_), Websocket::ctx_)
    , url_(std::move(url))
    , on_connected_(std::move(onConnectedCallback))
    , on_diconnected_(std::move(onDiconnectedCallback))
    , on_data_(std::move(onDataCallback))
    , on_error_(std::move(onErrorCallback))
    , w_buffer_(1048576)
{
    std::string protoco("wss");
    auto pos = url_.find("://");
    if (pos == std::string::npos)
    {
        pos = url_.find("/");
        if (pos == std::string::npos)
        {
            host_ = url_;
            path_ = "/";
        }
        else
        {
            host_ = url_.substr(0, pos);
            path_ = url_.substr(pos);
        }
    }
    else
    {
        protoco = url_.substr(0, pos);
        auto host_begin = pos + 3;
        auto pos1 = url_.find("/", host_begin);
        if (pos1 == std::string::npos)
        {
            host_ = url_.substr(host_begin);
            path_ = "/";
        }
        else
        {
            host_ = url_.substr(host_begin, pos1 - host_begin);
            path_ = url_.substr(pos1);
        }
    }
    
    pos = host_.find(':');
    if (pos != 3 && pos != 4 && pos != std::string::npos)
    {
        port_ = std::stoi(host_.substr(pos + 1));
        host_ = host_.substr(0, pos);
    }

    if (port_ == (uint_fast16_t)-1)
    {
        port_ = (protoco == "ws") ? 80 : 443;
    }
}

extern "C" void __signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        Websocket::shutdown();
    }
}

inline void Websocket::open()
{
    LOG_INFO("Opening WebSocket {}", url_);
    status_.store(Status::CONNECTING, std::memory_order_release);
    asio::co_spawn(Websocket::ioc_, do_wss_session(), asio::detached);

    auto init_service = init_service_thread_.load(std::memory_order_relaxed);
    if (init_service_thread_.compare_exchange_strong(init_service, true, std::memory_order_acq_rel) && !init_service)
    {
        std::signal(SIGINT, __signal_handler);
        std::signal(SIGTERM, __signal_handler);
        Websocket::run_.store(true, std::memory_order_release);
        Websocket::service_thread_ = std::thread([]() {
            LOG_INFO("Websocket service thread started.");
            while (run_.load(std::memory_order_relaxed))
            {
                try
                {
                    if (ioc_.stopped())
                    {
                        ioc_.restart();
                    }
                    ioc_.run();
                }
                catch(const std::exception& e)
                {
                    ioc_.restart();
                    LOG_ERROR(std::format("{}", e.what()));
                }
            }

            if (!ioc_.stopped()) [[unlikely]]
            {
                LOG_TRACE("call ioc_.stop at the end of run");
                ioc_.stop();
            }
            LOG_INFO("Websocket service thread exit");
            init_service_thread_.store(false, std::memory_order_release);
        });
    }
}

inline void Websocket::close()
{
    if (status_.load(std::memory_order_relaxed) < Status::DISCONNECTING)
    {
        LOG_INFO("Closing {}", url_);
        status_.store(Status::DISCONNECTING, std::memory_order_release);
        // Close the WebSocket connection
        ws_.async_close(
            websocket::close_code::normal,
            beast::bind_front_handler(
                &Websocket::on_close,
                shared_from_this()));
    }
}

inline void Websocket::send(const char* buffer, size_t len)
{
    auto index = w_buffer_.reserve(len);
    memcpy(w_buffer_[index], buffer, len);
    w_buffer_.publish(index, len);

    if (!in_writting_.load(std::memory_order_relaxed)) {
        in_writting_.store(true, std::memory_order_release);
        asio::post(ws_.get_executor(),
            beast::bind_front_handler(&Websocket::do_write, shared_from_this()));
    }
}

inline asio::awaitable<void> Websocket::do_wss_session()
{
    try
    {
        tcp::resolver resolver(asio::make_strand(Websocket::ioc_));
    
        // Look up the domain name
        auto result = co_await resolver.async_resolve(host_, std::to_string(port_), asio::use_awaitable);

        // Set SNI Hostname (many hosts need this to handshake successfully)
        if (!SSL_set_tlsext_host_name(ws_.next_layer().native_handle(), host_.c_str()))
        {
            beast::error_code ec{static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category()};
            throw beast::system_error{ec};
        }

        // Set a timeout on the operation
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

        // Make the connection on the IP address we get from DNS
        auto ep = co_await asio::async_connect(ws_.next_layer().lowest_layer(), result, asio::use_awaitable);

        // Update the host string. This will provide the value of the
        // Host HTTP header during the WebSocket handshake.
        // See https://tools.ietf.org/html/rfc7230#section-5.4
        host_ += ':' + std::to_string(ep.port());

        // Set a timeout on the operation
        beast::get_lowest_layer(ws_).expires_after(std::chrono::seconds(30));

        // Perform the SSL handshake
        co_await ws_.next_layer().async_handshake(ssl::stream_base::client, asio::use_awaitable);

        // Turn off the timeout on the tcp_stream, because
        // the websocket stream has its own timeout system.
        beast::get_lowest_layer(ws_).expires_never();
    
        // Set suggested timeout settings for the websocket
        ws_.set_option(
            websocket::stream_base::timeout::suggested(
                beast::role_type::client));
    
        // Set a decorator to change the User-Agent of the handshake
        ws_.set_option(websocket::stream_base::decorator(
            [](websocket::request_type& req)
            {
                req.set(http::field::user_agent,
                    std::string(BOOST_BEAST_VERSION_STRING) +
                        " websocket-client-coro");
            }));

        // Perform the WebSocket handshake
        co_await ws_.async_handshake(host_, path_, asio::use_awaitable);

        status_.store(Status::CONNECTED, std::memory_order_release);

        // start read messages
        ws_.async_read(
            r_buffer_,
            beast::bind_front_handler(
                &Websocket::on_read,
                shared_from_this()));

        on_connected_();
    }
    catch (beast::system_error const& se)
    {
        if (se.code() != websocket::error::closed)
        {
            on_error_(se.code().message());
        }
    }
    catch (std::exception const& e)
    {
        on_error_(e.what());
    }
}

inline void Websocket::do_write() {
    auto [msg, len] = w_buffer_.read(w_cursor_);
    if (msg && len) {
        LOG_DEBUG("--> {}", std::string_view(msg, len));
        ws_.async_write(
            asio::buffer(msg, len),
            beast::bind_front_handler(
                &Websocket::on_write,
                shared_from_this()));
    }
    else {
        in_writting_.store(false, std::memory_order_release);
    }
}

inline void Websocket::on_write(beast::error_code ec, std::size_t bytes_transferred)
{
    boost::ignore_unused(bytes_transferred);
    if(ec)
    {
        on_error_(std::format("Failed to read {}", ec.message()));
        return;
    }
    do_write();
}

inline void Websocket::on_read(beast::error_code ec, std::size_t bytes_transferred)
{
    if(ec)
    {
        on_error_(std::format("Failed to read {}", ec.message()));
        return;
    }

    LOG_TRACE("<-- {}", std::string((const char*)r_buffer_.data().data(), bytes_transferred));
    on_data_((const char*)r_buffer_.data().data(), bytes_transferred);
    r_buffer_.consume(bytes_transferred);

    if (status_.load(std::memory_order_relaxed) == Status::CONNECTED) {
        // read next message
        ws_.async_read(
            r_buffer_,
            beast::bind_front_handler(
                &Websocket::on_read,
                shared_from_this()));
    }
}

inline void Websocket::on_close(beast::error_code ec)
{
    if (ec && ec != beast::websocket::error::closed)
    {
        on_error_(ec.message());
    }

    // If we get here then the connection is closed gracefully
    LOG_INFO("Websocket {} closed", url_);
    status_.store(Status::DISCONNECTED, std::memory_order_release);
}

inline void Websocket::shutdown()
{
    if (run_.load(std::memory_order_relaxed))
    {
        run_.store(false, std::memory_order_release);
        ioc_.stop();
        if (service_thread_.joinable())
        {
            service_thread_.join();
        }
    }
}


// A Terminator class to ensure Websocket::shutdown() is called at program exit
struct WebsocketServiceTerminater
{
    WebsocketServiceTerminater() {
    }
    ~WebsocketServiceTerminater() {
        Websocket::shutdown();
    }
};

inline static WebsocketServiceTerminater s_websocket_service_terminater;


}   // end namespace slick_net