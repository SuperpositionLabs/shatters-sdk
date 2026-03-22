/**
 * @file shatters_c.h
 * @brief C API for the Shatters SDK - intended for FFI consumption.
 *
 * All functions are thread-safe unless otherwise noted.
 * Strings returned by the library are owned by the caller and must be freed
 * with shatters_string_free().  Byte buffers follow the same rule via
 * shatters_bytes_free().
 */

#ifndef SHATTERS_C_H
#define SHATTERS_C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- opaque handles ---------- */

typedef struct ShattersClient ShattersClient;

/* ---------- error codes ---------- */

typedef enum {
    SHATTERS_OK                = 0,
    SHATTERS_ERR_CRYPTO        = 1,
    SHATTERS_ERR_NETWORK       = 2,
    SHATTERS_ERR_INVALID_ARG   = 3,
    SHATTERS_ERR_TIMEOUT       = 4,
    SHATTERS_ERR_CONN_CLOSED   = 5,
    SHATTERS_ERR_ALREADY_CONN  = 6,
    SHATTERS_ERR_NOT_CONNECTED = 7,
    SHATTERS_ERR_CHANNEL       = 8,
    SHATTERS_ERR_PROTOCOL      = 9,
    SHATTERS_ERR_INTERNAL      = 10,
    SHATTERS_ERR_BUFFER_OVERFLOW = 11,
} ShattersErrorCode;

/* ---------- result struct ---------- */

typedef struct {
    ShattersErrorCode code;
    /** Heap-allocated error message, or NULL on success. Free with shatters_string_free(). */
    char* message;
} ShattersStatus;

/* ---------- byte buffer ---------- */

typedef struct {
    uint8_t* data;
    size_t   len;
} ShattersBytes;

/* ---------- contact ---------- */

typedef struct {
    char*    address;
    uint8_t  public_key[32];
    char*    display_name;
    int64_t  added_at;
} ShattersContact;

typedef struct {
    ShattersContact* items;
    size_t           count;
} ShattersContactList;

/* ---------- message history ---------- */

typedef struct {
    int64_t  id;
    char*    contact_address;
    uint8_t* plaintext;
    size_t   plaintext_len;
    int64_t  timestamp_ms;
    int      outgoing;
} ShattersHistoryMessage;

typedef struct {
    ShattersHistoryMessage* items;
    size_t                  count;
} ShattersHistoryList;

/* ---------- callbacks ---------- */

typedef void (*ShattersOnConnected)(void* ctx);
typedef void (*ShattersOnDisconnected)(void* ctx, ShattersErrorCode code, const char* message);
typedef void (*ShattersOnError)(void* ctx, ShattersErrorCode code, const char* message);
typedef void (*ShattersOnMessage)(void* ctx, const char* contact_address,
                                  const uint8_t* plaintext, size_t plaintext_len,
                                  int64_t timestamp_ms, int outgoing);

/* ---------- lifecycle ---------- */

ShattersStatus shatters_create(
    const char* db_path,
    const char* db_pass,
    const char* server_host,
    uint16_t    server_port,
    const uint8_t* tls_pin, size_t tls_pin_len,
    int auto_reconnect,
    ShattersClient** out
);

void shatters_destroy(ShattersClient* client);

/* ---------- connection ---------- */

ShattersStatus shatters_connect(ShattersClient* client);
void           shatters_disconnect(ShattersClient* client);
int            shatters_is_connected(const ShattersClient* client);

/* ---------- identity ---------- */

/** Returns heap-allocated address string. Caller must free with shatters_string_free(). */
char* shatters_address(const ShattersClient* client);

/** Copies the 32-byte Ed25519 public key into out_pk. */
ShattersStatus shatters_public_key(const ShattersClient* client, uint8_t out_pk[32]);

/* ---------- messaging ---------- */

ShattersStatus shatters_send_message(
    ShattersClient* client,
    const char* contact_address,
    const uint8_t* plaintext, size_t plaintext_len
);

ShattersStatus shatters_message_history(
    ShattersClient* client,
    const char* contact_address,
    size_t limit,
    size_t offset,
    ShattersHistoryList* out
);

ShattersStatus shatters_upload_prekey_bundle(ShattersClient* client, uint32_t num_one_time);
ShattersStatus shatters_resume_conversations(ShattersClient* client);

/* ---------- contacts ---------- */

ShattersStatus shatters_add_contact(
    ShattersClient* client,
    const char* address,
    const uint8_t public_key[32],
    const char* display_name
);

ShattersStatus shatters_remove_contact(ShattersClient* client, const char* address);
ShattersStatus shatters_list_contacts(ShattersClient* client, ShattersContactList* out);

/* ---------- callbacks ---------- */

void shatters_on_connected(ShattersClient* client, ShattersOnConnected cb, void* ctx);
void shatters_on_disconnected(ShattersClient* client, ShattersOnDisconnected cb, void* ctx);
void shatters_on_error(ShattersClient* client, ShattersOnError cb, void* ctx);
void shatters_on_message(ShattersClient* client, ShattersOnMessage cb, void* ctx);

/* ---------- key exchange ---------- */

ShattersStatus shatters_start_conversation(
    ShattersClient* client,
    const char* contact_address,
    const uint8_t* bundle_data, size_t bundle_len,
    const uint8_t* first_message, size_t first_message_len
);

ShattersStatus shatters_fetch_bundle(
    ShattersClient* client,
    const char* address,
    uint32_t timeout_secs,
    ShattersBytes* out
);

/* ---------- free helpers ---------- */

void shatters_string_free(char* s);
void shatters_bytes_free(ShattersBytes* buf);
void shatters_contact_list_free(ShattersContactList* list);
void shatters_history_list_free(ShattersHistoryList* list);
void shatters_status_free(ShattersStatus* status);

#ifdef __cplusplus
}
#endif

#endif
