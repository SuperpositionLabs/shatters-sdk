#include <shatters/transport/quic_transport.hpp>
#include <shatters/transport/channel_cipher.hpp>

#include <msquic.h>
#include <sodium.h>
#include <spdlog/spdlog.h>

#include <mutex>
#include <thread>
#include <atomic>
#include <memory>

namespace shatters
{
    namespace framing
    {
        constexpr uint32_t MAX_FRAME_SIZE = 1 * 1024 * 1024;

        static std::vector<uint8_t> encode(const uint8_t* data, size_t len)
        {
            if (len > MAX_FRAME_SIZE)
                return {};

            std::vector<uint8_t> frame(4 + len);
            
            uint32_t len_be = static_cast<uint32_t>(len);
            frame[0] = (len_be >> 24) & 0xFF;
            frame[1] = (len_be >> 16) & 0xFF;
            frame[2] = (len_be >> 8) & 0xFF;
            frame[3] = len_be & 0xFF;
            std::memcpy(frame.data() + 4, data, len);
            
            return frame;
        }

        static uint32_t decode_length(const uint8_t* header)
        {
            return (static_cast<uint32_t>(header[0]) << 24) |
                   (static_cast<uint32_t>(header[1]) << 16) |
                   (static_cast<uint32_t>(header[2]) << 8)  |
                    static_cast<uint32_t>(header[3]);
        }
    }

    struct MsQuicContext {
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
            if (QUIC_FAILED(status)) {
                spdlog::critical("quic open failed: 0x{:X}", status);
                return nullptr;
            }

            QUIC_REGISTRATION_CONFIG reg = {"$hatter$", QUIC_EXECUTION_PROFILE_LOW_LATENCY};
            status = ctx->api->RegistrationOpen(&reg, &ctx->registration);
            if (QUIC_FAILED(status)) {
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

        explicit SendBuffer(std::vector<uint8_t> data) : storage(std::move(data))
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
        uint16_t port = 0;
        
        std::shared_ptr<MsQuicContext> quic_ctx;
    
        HQUIC configuration = nullptr;
        HQUIC stream        = nullptr;
        HQUIC connection    = nullptr;
    
        std::vector<uint8_t> server_pk;
    
        std::unique_ptr<IChannelCipher> cipher;
    
        std::mutex callback_mutex;
        FrameCallback on_frame_cb;
        StateCallback on_state_cb;
    
        std::mutex recv_mutex;
        std::vector<uint8_t> recv_buf;
        size_t read_pos = 0;
    
        std::mutex handshake_mutex;
        std::condition_variable handshake_cv;
        bool handshake_complete = false;
        QUIC_STATUS handshake_status = QUIC_STATUS_PENDING;

        std::mutex shutdown_mutex;
        std::condition_variable shutdown_cv;
        bool connection_shutdown_complete = false;
        bool stream_shutdown_complete = false;
    
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

                while (recv_buf.size() - read_pos >= 4)
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
                    if (available < 4 + frame_len)
                        break;
    
                    const uint8_t* payload = recv_buf.data() + read_pos + 4;
                    read_pos += 4 + frame_len;
    
                    if (cipher && cipher->is_established())
                    {
                        auto result = cipher->decrypt(payload, frame_len);
                        if (result.is_ok())
                            frames.push_back(std::move(result).take_value());
                        else
                            spdlog::warn("decrypt failed: {}", result.error().message);
                    }
                }

                if (read_pos > recv_buf.capacity() / 2)
                {
                    recv_buf.erase(recv_buf.begin(), recv_buf.begin() + static_cast<ptrdiff_t>(read_pos));
                    read_pos = 0;
                }
            }

            for (auto& frame : frames)
                dispatch_frame(std::move(frame));
        }

        static QUIC_STATUS QUIC_API connection_callback(HQUIC conn, void* ctx, QUIC_CONNECTION_EVENT* event)
        {
            auto* self = static_cast<Impl*>(ctx);

            switch (event->Type)
            {
                case QUIC_CONNECTION_EVENT_CONNECTED:
                    spdlog::info("quic connected, negotiated alpn: {}",
                        std::string_view(
                            reinterpret_cast<const char*>(event->CONNECTED.NegotiatedAlpn + 1),
                            event->CONNECTED.NegotiatedAlpn[0]
                        )
                    );

                    {
                        std::lock_guard lock(self->handshake_mutex);
                        self->handshake_complete = true;
                        self->handshake_status = QUIC_STATUS_SUCCESS;
                    }
                    self->handshake_cv.notify_one();
                    break;

                case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
                    spdlog::warn("quic shutdown by transport: 0x{:x}", event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
                    self->set_state(ConnectionState::Disconnected);
                    break;

                case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
                    spdlog::info("quic shutdown by peer, code: {}", event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
                    self->set_state(ConnectionState::Disconnected);
                    break;

                case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
                {
                    std::lock_guard lock(self->shutdown_mutex);
                    self->connection_shutdown_complete = true;
                }
                    self->shutdown_cv.notify_one();
                    break;
                
                case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
                    self->quic_ctx->api->StreamClose(event->PEER_STREAM_STARTED.Stream);
                    break;

                default:
                    break;
            }

            return QUIC_STATUS_SUCCESS;
        }

        static QUIC_STATUS QUIC_API stream_callback(HQUIC stream, void* ctx, QUIC_STREAM_EVENT* event)
        {
            auto* self = static_cast<Impl*>(ctx);

            switch (event->Type)
            {
                case QUIC_STREAM_EVENT_RECEIVE:
                    for (uint32_t i = 0; i < event->RECEIVE.BufferCount; ++i)
                    {
                        self->on_data_received(
                            event->RECEIVE.Buffers[i].Buffer,
                            event->RECEIVE.Buffers[i].Length
                        );
                    }
                    break;

                case QUIC_STREAM_EVENT_SEND_COMPLETE:
                    delete static_cast<SendBuffer*>(event->SEND_COMPLETE.ClientContext);
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

    QuicTransport::QuicTransport(Config config) : impl_(std::make_unique<Impl>())
    {
        impl_->config = std::move(config);
        impl_->cipher = std::make_unique<SodiumChannelCipher>();
        impl_->quic_ctx = MsQuicContext::get();
    }

    QuicTransport::~QuicTransport()
    {
        disconnect();
    }

    Result<void> QuicTransport::connect(
        const std::string& host, uint16_t port,
        const uint8_t* server_pk, size_t pk_len
    )
    {
        if (!impl_->quic_ctx)
            return Error{ErrorCode::NetworkError, "msquic not initialized"};

        if (state() != ConnectionState::Disconnected)
            return Error{ErrorCode::NetworkError, "already connected or connecting"};

        if (pk_len < crypto_kx_PUBLICKEYBYTES)
            return  Error{ErrorCode::InvalidArgument, "invalid server public key"};

        impl_->host = host;
        impl_->port = port;
        impl_->server_pk.assign(server_pk, server_pk + pk_len);
        impl_->set_state(ConnectionState::Connecting);

        QUIC_BUFFER alpn_buffer;
        std::string alpn = impl_->config.tls_alpn;
        alpn_buffer.Length = static_cast<uint32_t>(alpn.size());
        alpn_buffer.Buffer = reinterpret_cast<uint8_t*>(alpn.data());

        QUIC_STATUS status = impl_->quic_ctx->api->ConfigurationOpen(
            impl_->quic_ctx->registration, &alpn_buffer, 1,
            nullptr, 0, nullptr,
            &impl_->configuration
        );
        if (QUIC_FAILED(status))
        {
            impl_->set_state(ConnectionState::Disconnected);
            return Error{ErrorCode::NetworkError, "configuration open failed"};
        }

        QUIC_CREDENTIAL_CONFIG cred_config = {};
        cred_config.Type  = QUIC_CREDENTIAL_TYPE_NONE;
        cred_config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT |
                            QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;  /* @todo: pin via callback */

        status = impl_->quic_ctx->api->ConfigurationLoadCredential(impl_->configuration, &cred_config);
        if (QUIC_FAILED(status))
        {
            impl_->quic_ctx->api->ConfigurationClose(impl_->configuration);
            impl_->set_state(ConnectionState::Disconnected);
            return Error{ErrorCode::NetworkError, "tls credential load failed"};
        }

        QUIC_SETTINGS settings = {};
        settings.IsSet.IdleTimeoutMs = TRUE;
        settings.IdleTimeoutMs = impl_->config.idle_timeout_ms;
        settings.IsSet.KeepAliveIntervalMs = TRUE;
        settings.KeepAliveIntervalMs = impl_->config.keep_alive_ms;

        impl_->quic_ctx->api->SetParam(impl_->configuration, QUIC_PARAM_CONFIGURATION_SETTINGS, sizeof(settings), &settings);

        status = impl_->quic_ctx->api->ConnectionOpen(
            impl_->quic_ctx->registration,
            Impl::connection_callback, impl_.get(),
            &impl_->connection
        );
        if (QUIC_FAILED(status))
        {
            impl_->quic_ctx->api->ConfigurationClose(impl_->configuration);
            impl_->set_state(ConnectionState::Disconnected);
            return Error{ErrorCode::NetworkError, "connection open failed"};
        }

        status = impl_->quic_ctx->api->ConnectionStart(
            impl_->connection,
            impl_->configuration,
            QUIC_ADDRESS_FAMILY_UNSPEC,
            impl_->host.c_str(),
            impl_->port
        );
        if (QUIC_FAILED(status))
        {
            impl_->quic_ctx->api->ConnectionClose(impl_->connection);
            impl_->quic_ctx->api->ConfigurationClose(impl_->configuration);
            impl_->set_state(ConnectionState::Disconnected);
            return Error{ErrorCode::NetworkError, "connection start failed"};
        }

        {
            std::unique_lock lock(impl_->handshake_mutex);
            impl_->handshake_cv.wait_for(
                lock, std::chrono::seconds(10),
                [this] { return impl_->handshake_complete; }
            );
            if (!impl_->handshake_complete)
            {
                disconnect();
                return Error{ErrorCode::NetworkError, "quic handshake timeout"};
            }
        }

        status = impl_->quic_ctx->api->StreamOpen(
            impl_->connection, QUIC_STREAM_OPEN_FLAG_NONE,
            Impl::stream_callback, impl_.get(),
            &impl_->stream
        );
        if (QUIC_FAILED(status))
        {
            disconnect();
            return Error{ErrorCode::NetworkError, "stream open failed"};
        }

        status = impl_->quic_ctx->api->StreamStart(impl_->stream, QUIC_STREAM_START_FLAG_NONE);
        if (QUIC_FAILED(status))
        {
            disconnect();
            return Error{ErrorCode::NetworkError, "stream start failed"};
        }

        impl_->set_state(ConnectionState::HandshakingNoise);
        SHATTERS_TRY(do_noise_handshake());
        impl_->set_state(ConnectionState::Connected);

        return std::monostate{};
    }

    void QuicTransport::disconnect()
    {
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
        
        if (impl_->stream) {
            impl_->quic_ctx->api->StreamClose(impl_->stream);
            impl_->stream = nullptr;
        }
        if (impl_->connection) {
            impl_->quic_ctx->api->ConnectionClose(impl_->connection);
            impl_->connection = nullptr;
        }
        if (impl_->configuration)
        {
            impl_->quic_ctx->api->ConfigurationClose(impl_->configuration);
            impl_->configuration = nullptr;
        }

        impl_->cipher->reset();
        impl_->handshake_complete = false;
        impl_->connection_shutdown_complete = false;
        impl_->stream_shutdown_complete = false;

        std::lock_guard lock(impl_->recv_mutex);
        impl_->recv_buf.clear();
        impl_->read_pos = 0;
    }

    Result<void> QuicTransport::send(const uint8_t* data, size_t len)
    {
        if (!is_connected())
            return Error{ErrorCode::NetworkError, "not connected"};

        auto enc_result = impl_->cipher->encrypt(data, len);
        if (enc_result.is_err())
            return enc_result.error();
        auto encrypted = std::move(enc_result).take_value();

        auto framed = framing::encode(encrypted.data(), encrypted.size());
        if (framed.empty())
            return Error{ErrorCode::InvalidArgument, "frame too large"};

        auto* buf = new SendBuffer(std::move(framed));

        QUIC_STATUS status = impl_->quic_ctx->api->StreamSend(impl_->stream, &buf->quic_buf, 1, QUIC_SEND_FLAG_NONE, buf);
        if (QUIC_FAILED(status))
        {
            delete buf;
            return Error{ErrorCode::NetworkError, "stream send failed"};
        }

        return std::monostate{};
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

    Result<void> QuicTransport::do_noise_handshake()
    {
        auto handshake = framing::encode(
            impl_->cipher->local_public_key(),
            impl_->cipher->local_public_key_size()
        );

        auto* buf = new SendBuffer(std::move(handshake));
        
        QUIC_STATUS status = impl_->quic_ctx->api->StreamSend(impl_->stream, &buf->quic_buf, 1, QUIC_SEND_FLAG_NONE, buf);
        if (QUIC_FAILED(status))
        {
            delete buf;
            return Error{ErrorCode::NetworkError, "failed to send handshake"};
        }

        SHATTERS_TRY(impl_->cipher->initialize_as_client(
            impl_->server_pk.data(),
            impl_->server_pk.size()
        ));

        return std::monostate{};
    }

    void QuicTransport::schedule_reconnect()
    {
        spdlog::info("connection lost, reconnection will be attempted by client");
    }

}
