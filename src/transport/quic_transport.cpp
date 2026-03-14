#include <shatters/transport/quic_transport.hpp>
#include <shatters/protocol/framing.hpp>

#include <msquic.h>
#include <sodium.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#ifdef _WIN32
#include <wincrypt.h>
#endif

namespace shatters
{

struct MsQuicContext
{
    HQUIC registration = nullptr;
    const QUIC_API_TABLE* api = nullptr;

    ~MsQuicContext()
    {
        if (registration && api)
            api->RegistrationClose(registration);
        if (api)
            MsQuicClose(api);
    }

    MsQuicContext(const MsQuicContext&) = delete;
    MsQuicContext& operator=(const MsQuicContext&) = delete;

    static std::shared_ptr<MsQuicContext> get()
    {
        static std::mutex mu;
        static std::weak_ptr<MsQuicContext> weak;

        std::lock_guard lock(mu);
        if (auto existing = weak.lock())
            return existing;

        auto ctx = std::shared_ptr<MsQuicContext>(new MsQuicContext());

        QUIC_STATUS status = MsQuicOpen2(&ctx->api);
        if (QUIC_FAILED(status))
        {
            spdlog::critical("quic open failed: 0x{:X}", status);
            return nullptr;
        }

        QUIC_REGISTRATION_CONFIG reg = { "$hatter$", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
        status = ctx->api->RegistrationOpen(&reg, &ctx->registration);
        if (QUIC_FAILED(status))
        {
            spdlog::critical("quic registration failed: 0x{:X}", status);
            return nullptr;
        }

        weak = ctx;
        return ctx;
    }

private:
    MsQuicContext() = default;
};

struct SendBuffer
{
    std::vector<uint8_t> storage;
    QUIC_BUFFER quic_buf{};

    explicit SendBuffer(std::vector<uint8_t> data)
        : storage(std::move(data))
    {
        quic_buf.Length = static_cast<uint32_t>(storage.size());
        quic_buf.Buffer = storage.data();
    }

    SendBuffer(const SendBuffer&) = delete;
    SendBuffer& operator=(const SendBuffer&) = delete;
};

struct QuicTransport::Impl
{
    Config config;
    std::atomic<ConnectionState> conn_state{ConnectionState::Disconnected};

    std::string host;
    uint16_t    port = 0;

    std::shared_ptr<MsQuicContext> quic_ctx;

    HQUIC configuration = nullptr;
    HQUIC stream        = nullptr;
    HQUIC connection    = nullptr;

    std::mutex    callback_mutex;
    FrameCallback on_frame_cb;
    StateCallback on_state_cb;

    std::mutex           recv_mutex;
    std::vector<uint8_t> recv_buf;
    size_t               read_pos = 0;

    std::mutex              shutdown_mutex;
    std::condition_variable shutdown_cv;
    bool connection_shutdown_complete = false;
    bool stream_shutdown_complete     = false;

    std::atomic<bool> user_disconnecting{false};
    std::atomic<bool> reconnect_in_progress{false};
    std::jthread      reconnect_thread;

    void set_state(ConnectionState new_state)
    {
        conn_state.store(new_state, std::memory_order_release);

        std::lock_guard lock(callback_mutex);
        if (on_state_cb)
            on_state_cb(new_state);
    }

    void dispatch_frame(std::vector<uint8_t> data)
    {
        std::lock_guard lock(callback_mutex);
        if (on_frame_cb)
            on_frame_cb(std::move(data));
    }

    void on_data_received(const uint8_t* data, size_t len)
    {
        std::vector<std::vector<uint8_t>> frames;
        {
            std::lock_guard lock(recv_mutex);
            recv_buf.insert(recv_buf.end(), data, data + len);

            while (recv_buf.size() - read_pos >= framing::HEADER_SIZE)
            {
                uint32_t frame_len = framing::decode_length(recv_buf.data() + read_pos);

                if (frame_len > framing::MAX_FRAME_SIZE)
                {
                    spdlog::error("frame too large ({} bytes), dropping buffer", frame_len);
                    recv_buf.clear();
                    read_pos = 0;
                    return;
                }

                size_t available = recv_buf.size() - read_pos;
                if (available < framing::HEADER_SIZE + frame_len)
                    break;

                const uint8_t* payload = recv_buf.data() + read_pos + framing::HEADER_SIZE;
                read_pos += framing::HEADER_SIZE + frame_len;

                frames.emplace_back(payload, payload + frame_len);
            }

            if (read_pos > recv_buf.capacity() / 2)
            {
                recv_buf.erase(
                    recv_buf.begin(),
                    recv_buf.begin() + static_cast<ptrdiff_t>(read_pos)
                );
                read_pos = 0;
            }
        }

        for (auto& frame : frames)
            dispatch_frame(std::move(frame));
    }

    void cleanup_resources()
    {
        if (stream)
        {
            quic_ctx->api->StreamClose(stream);
            stream = nullptr;
        }
        if (connection)
        {
            quic_ctx->api->ConnectionClose(connection);
            connection = nullptr;
        }
        if (configuration)
        {
            quic_ctx->api->ConfigurationClose(configuration);
            configuration = nullptr;
        }

        connection_shutdown_complete = false;
        stream_shutdown_complete     = false;

        std::lock_guard lock(recv_mutex);
        recv_buf.clear();
        read_pos = 0;
    }

    Status try_connect()
    {
        QUIC_BUFFER alpn_buffer;
        std::string alpn = config.tls_alpn;
        alpn_buffer.Length = static_cast<uint32_t>(alpn.size());
        alpn_buffer.Buffer = reinterpret_cast<uint8_t*>(alpn.data());

        QUIC_SETTINGS settings{};
        settings.IsSet.IdleTimeoutMs       = TRUE;
        settings.IdleTimeoutMs             = config.idle_timeout_ms;
        settings.IsSet.KeepAliveIntervalMs = TRUE;
        settings.KeepAliveIntervalMs       = config.keep_alive_ms;

        QUIC_STATUS status = quic_ctx->api->ConfigurationOpen(
            quic_ctx->registration,
            &alpn_buffer, 1,
            &settings, sizeof(settings),
            nullptr,
            &configuration
        );
        if (QUIC_FAILED(status))
            return Error{ErrorCode::NetworkError, "configuration open failed"};

        QUIC_CREDENTIAL_CONFIG cred_config{};
        cred_config.Type  = QUIC_CREDENTIAL_TYPE_NONE;
        cred_config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;

        if (config.tls_pin_sha256.empty())
            cred_config.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        else
            cred_config.Flags |= QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED;

        status = quic_ctx->api->ConfigurationLoadCredential(configuration, &cred_config);
        if (QUIC_FAILED(status))
        {
            quic_ctx->api->ConfigurationClose(configuration);
            configuration = nullptr;
            return Error{ErrorCode::NetworkError, "tls credential load failed"};
        }

        status = quic_ctx->api->ConnectionOpen(
            quic_ctx->registration,
            connection_callback, this,
            &connection
        );
        if (QUIC_FAILED(status))
        {
            quic_ctx->api->ConfigurationClose(configuration);
            configuration = nullptr;
            return Error{ErrorCode::NetworkError, "connection open failed"};
        }

        status = quic_ctx->api->ConnectionStart(
            connection, configuration,
            QUIC_ADDRESS_FAMILY_UNSPEC,
            host.c_str(), port
        );
        if (QUIC_FAILED(status))
        {
            quic_ctx->api->ConnectionClose(connection);
            connection = nullptr;
            quic_ctx->api->ConfigurationClose(configuration);
            configuration = nullptr;
            return Error{ErrorCode::NetworkError, "connection start failed"};
        }

        status = quic_ctx->api->StreamOpen(
            connection, QUIC_STREAM_OPEN_FLAG_NONE,
            stream_callback, this,
            &stream
        );
        if (QUIC_FAILED(status))
        {
            quic_ctx->api->ConnectionClose(connection);
            connection = nullptr;
            quic_ctx->api->ConfigurationClose(configuration);
            configuration = nullptr;
            return Error{ErrorCode::NetworkError, "stream open failed"};
        }

        status = quic_ctx->api->StreamStart(stream, QUIC_STREAM_START_FLAG_NONE);
        if (QUIC_FAILED(status))
        {
            quic_ctx->api->StreamClose(stream);
            stream = nullptr;
            quic_ctx->api->ConnectionClose(connection);
            connection = nullptr;
            quic_ctx->api->ConfigurationClose(configuration);
            configuration = nullptr;
            return Error{ErrorCode::NetworkError, "stream start failed"};
        }

        return Status{};
    }

    void begin_reconnect()
    {
        if (!config.auto_reconnect || user_disconnecting.load())
            return;

        if (reconnect_in_progress.exchange(true))
            return;

        reconnect_thread = std::jthread([this](std::stop_token stoken)
        {
            uint32_t delay = config.reconnect_delay_ms;
            set_state(ConnectionState::Reconnecting);

            {
                std::unique_lock lock(shutdown_mutex);
                shutdown_cv.wait_for(lock, std::chrono::seconds(5), [this] {
                    return (!stream     || stream_shutdown_complete) &&
                           (!connection || connection_shutdown_complete);
                });
            }

            while (!stoken.stop_requested())
            {
                auto deadline = std::chrono::steady_clock::now()
                              + std::chrono::milliseconds(delay);
                while (std::chrono::steady_clock::now() < deadline)
                {
                    if (stoken.stop_requested())
                    {
                        reconnect_in_progress.store(false);
                        return;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }

                if (stoken.stop_requested())
                    break;

                cleanup_resources();

                spdlog::info("reconnecting to {}:{} (delay={}ms)", host, port, delay);

                auto status = try_connect();
                if (status.is_ok())
                {
                    spdlog::info("reconnected successfully");
                    set_state(ConnectionState::Connected);
                    reconnect_in_progress.store(false);
                    return;
                }

                spdlog::warn("reconnect attempt failed: {}", status.error().message);

                delay = (std::min)(delay * 2, config.max_reconnect_delay_ms);
            }

            set_state(ConnectionState::Disconnected);
            reconnect_in_progress.store(false);
        });
    }

    static QUIC_STATUS QUIC_API connection_callback(
        HQUIC /*conn*/, void* ctx, QUIC_CONNECTION_EVENT* event)
    {
        auto* self = static_cast<Impl*>(ctx);

        switch (event->Type)
        {
            case QUIC_CONNECTION_EVENT_CONNECTED:
                spdlog::info("quic connected, negotiated alpn: {}",
                    std::string_view(
                        reinterpret_cast<const char*>(
                            event->CONNECTED.NegotiatedAlpn + 1),
                        event->CONNECTED.NegotiatedAlpn[0]));
                break;

            case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
                spdlog::warn("quic shutdown by transport: 0x{:x}", event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
                self->set_state(ConnectionState::Disconnected);
                self->begin_reconnect();
                break;

            case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
                spdlog::info("quic shutdown by peer, code: {}", event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
                self->set_state(ConnectionState::Disconnected);
                self->begin_reconnect();
                break;

            case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            {
                std::lock_guard lock(self->shutdown_mutex);
                self->connection_shutdown_complete = true;
            }
                self->shutdown_cv.notify_one();
                break;

            case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
                self->quic_ctx->api->StreamClose(
                    event->PEER_STREAM_STARTED.Stream);
                break;

            case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED:
            {
                if (self->config.tls_pin_sha256.empty())
                    break;

#ifdef _WIN32
                auto* cert_ctx = reinterpret_cast<const CERT_CONTEXT*>(
                    event->PEER_CERTIFICATE_RECEIVED.Certificate);
                if (!cert_ctx || !cert_ctx->pbCertEncoded)
                {
                    spdlog::error("tls pin: no peer certificate provided");
                    return QUIC_STATUS_INTERNAL_ERROR;
                }

                unsigned char hash[crypto_hash_sha256_BYTES];
                crypto_hash_sha256(
                    hash,
                    cert_ctx->pbCertEncoded,
                    cert_ctx->cbCertEncoded);

                if (self->config.tls_pin_sha256.size()
                    != crypto_hash_sha256_BYTES ||
                    sodium_memcmp(
                        hash,
                        self->config.tls_pin_sha256.data(),
                        crypto_hash_sha256_BYTES) != 0)
                {
                    spdlog::error("tls certificate pin mismatch");
                    return QUIC_STATUS_INTERNAL_ERROR;
                }

                spdlog::info("tls certificate pin verified");
#else
                spdlog::warn("tls certificate pinning is not implemented");
#endif
                break;
            }

            default:
                break;
        }

        return QUIC_STATUS_SUCCESS;
    }

    static QUIC_STATUS QUIC_API stream_callback(
        HQUIC /*stream*/, void* ctx, QUIC_STREAM_EVENT* event)
    {
        auto* self = static_cast<Impl*>(ctx);

        switch (event->Type)
        {
            case QUIC_STREAM_EVENT_RECEIVE:
                for (uint32_t i = 0; i < event->RECEIVE.BufferCount; ++i)
                {
                    self->on_data_received(
                        event->RECEIVE.Buffers[i].Buffer,
                        event->RECEIVE.Buffers[i].Length);
                }
                break;

            case QUIC_STREAM_EVENT_SEND_COMPLETE:
                delete static_cast<SendBuffer*>(
                    event->SEND_COMPLETE.ClientContext);
                break;

            case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
                spdlog::debug("peer finished sending on stream");
                break;

            case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            {
                std::lock_guard lock(self->shutdown_mutex);
                self->stream_shutdown_complete = true;
            }
                self->shutdown_cv.notify_one();
                break;

            default:
                break;
        }

        return QUIC_STATUS_SUCCESS;
    }
};

QuicTransport::QuicTransport(Config config)
    : impl_(std::make_unique<Impl>())
{
    impl_->config   = std::move(config);
    impl_->quic_ctx = MsQuicContext::get();
}

QuicTransport::~QuicTransport()
{
    disconnect();
}

Status QuicTransport::connect(const std::string& host, uint16_t port)
{
    if (!impl_->quic_ctx)
        return Error{ErrorCode::NetworkError, "msquic not initialized"};

    if (state() != ConnectionState::Disconnected)
        return Error{ErrorCode::AlreadyConnected, "already connected or connecting"};

    impl_->host = host;
    impl_->port = port;
    impl_->user_disconnecting.store(false);
    impl_->set_state(ConnectionState::Connecting);

    auto status = impl_->try_connect();
    if (status.is_err())
    {
        impl_->set_state(ConnectionState::Disconnected);
        return status;
    }

    impl_->set_state(ConnectionState::Connected);
    return Status{};
}

void QuicTransport::disconnect()
{
    impl_->user_disconnecting.store(true);

    if (impl_->reconnect_thread.joinable())
    {
        impl_->reconnect_thread.request_stop();
        impl_->reconnect_thread.join();
    }
    impl_->reconnect_in_progress.store(false);

    if (state() == ConnectionState::Disconnected)
        return;

    impl_->set_state(ConnectionState::Disconnected);

    if (impl_->stream)
        impl_->quic_ctx->api->StreamShutdown(impl_->stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);

    if (impl_->connection)
        impl_->quic_ctx->api->ConnectionShutdown(impl_->connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);

    {
        std::unique_lock lock(impl_->shutdown_mutex);
        impl_->shutdown_cv.wait_for(
            lock, std::chrono::seconds(5), [this] {
                return (!impl_->stream     || impl_->stream_shutdown_complete) &&
                       (!impl_->connection || impl_->connection_shutdown_complete);
            });
    }

    impl_->cleanup_resources();
}

Status QuicTransport::publish(ByteSpan data)
{
    if (!is_connected())
        return Error{ErrorCode::NotConnected, "not connected"};

    auto framed = framing::encode(data.data(), data.size());
    if (framed.empty())
        return Error{ErrorCode::BufferOverflow, "frame too large"};

    auto* buf = new SendBuffer(std::move(framed));

    QUIC_STATUS status = impl_->quic_ctx->api->StreamSend(impl_->stream, &buf->quic_buf, 1, QUIC_SEND_FLAG_NONE, buf);
    if (QUIC_FAILED(status))
    {
        delete buf;
        return Error{ErrorCode::NetworkError, "stream send failed"};
    }

    return Status{};
}

ConnectionState QuicTransport::state() const
{
    return impl_->conn_state.load(std::memory_order_acquire);
}

bool QuicTransport::is_connected() const
{
    return state() == ConnectionState::Connected;
}

void QuicTransport::on_frame(FrameCallback callback)
{
    std::lock_guard lock(impl_->callback_mutex);
    impl_->on_frame_cb = std::move(callback);
}

void QuicTransport::on_state_change(StateCallback callback)
{
    std::lock_guard lock(impl_->callback_mutex);
    impl_->on_state_cb = std::move(callback);
}

void QuicTransport::schedule_reconnect()
{
    impl_->begin_reconnect();
}

}
