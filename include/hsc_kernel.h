#ifndef HSC_KERNEL_H
#define HSC_KERNEL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// -----------------------------------------------------------------------------
// Global API Return Codes
// -----------------------------------------------------------------------------

#define HSC_OK                                     0
#define HSC_ERROR_GENERAL                         -1
#define HSC_ERROR_ALLOCATION_FAILED               -2 // Memory allocation failed (including secure memory).
#define HSC_ERROR_INVALID_ARGUMENT                -3 // Arguments provided to the function are invalid.
#define HSC_ERROR_FILE_IO                         -4 // File read/write operation failed.
#define HSC_ERROR_CRYPTO_OPERATION                -5 // Underlying cryptographic operation failed.
#define HSC_ERROR_PKI_OPERATION                   -6 // Underlying PKI operation failed.
#define HSC_ERROR_INVALID_FORMAT                  -7 // Input data format is invalid (e.g., bad PEM).
#define HSC_ERROR_SIGNATURE_VERIFICATION_FAILED   -8 // Sender signature verification failed.

// Certificate Verification Error Codes
#define HSC_ERROR_CERT_CHAIN_OR_VALIDITY         -10 // Chain validation failed, or cert is expired/not yet valid.
#define HSC_ERROR_CERT_SUBJECT_MISMATCH          -11 // Certificate Subject (CN) does not match expected value.
#define HSC_ERROR_CERT_REVOKED                   -12 // Certificate has been explicitly revoked.
#define HSC_ERROR_CERT_OCSP_UNAVAILABLE          -13 // OCSP check failed due to network/server issues (Fail-Closed).
#define HSC_ERROR_CERT_OCSP_STATUS_UNKNOWN       -14 // OCSP server reports unknown status (treated as revoked).
#define HSC_ERROR_CERT_NO_OCSP_URI               -15 // Certificate lacks AIA/OCSP extension (Fail-Closed).

// Legacy Certificate Verification Codes (Maintained for backward compatibility)
#define HSC_VERIFY_SUCCESS                        HSC_OK
#define HSC_VERIFY_ERROR_GENERAL                  HSC_ERROR_GENERAL
#define HSC_VERIFY_ERROR_CHAIN_OR_VALIDITY        HSC_ERROR_CERT_CHAIN_OR_VALIDITY
#define HSC_VERIFY_ERROR_SUBJECT_MISMATCH         HSC_ERROR_CERT_SUBJECT_MISMATCH
#define HSC_VERIFY_ERROR_REVOKED                  HSC_ERROR_CERT_REVOKED
#define HSC_VERIFY_ERROR_OCSP_UNAVAILABLE         HSC_ERROR_CERT_OCSP_UNAVAILABLE
#define HSC_VERIFY_ERROR_OCSP_STATUS_UNKNOWN      HSC_ERROR_CERT_OCSP_STATUS_UNKNOWN
#define HSC_VERIFY_ERROR_REVOKED_OR_OCSP_FAILED   HSC_ERROR_CERT_OCSP_UNAVAILABLE

// -----------------------------------------------------------------------------
// Public Constants
// -----------------------------------------------------------------------------

#define HSC_MASTER_PUBLIC_KEY_BYTES 32
#define HSC_MASTER_SECRET_KEY_BYTES 64
#define HSC_SESSION_KEY_BYTES       32

// Salt length matches Libsodium's Argon2id implementation (crypto_pwhash_SALTBYTES).
#define HSC_KDF_SALT_BYTES          16

// Stream Encryption (XChaCha20-Poly1305 SecretStream) Constants
#define HSC_STREAM_HEADER_BYTES     24
#define HSC_STREAM_TAG_BYTES        16
#define HSC_STREAM_CHUNK_OVERHEAD   (HSC_STREAM_TAG_BYTES)

// Single-shot AEAD Encryption Constants
#define HSC_AEAD_NONCE_BYTES        24
#define HSC_AEAD_TAG_BYTES          16
#define HSC_AEAD_OVERHEAD_BYTES     (HSC_AEAD_NONCE_BYTES + HSC_AEAD_TAG_BYTES)

// Key Encapsulation Overhead Constants
// Structure: [Nonce (24)] + [Ephemeral_PK (32)] + [Signature (64)] + [MAC (16)]
#define HSC_BOX_NONCE_BYTES         24
#define HSC_BOX_MAC_BYTES           16
#define HSC_EPHEMERAL_PK_BYTES      32
#define HSC_SIGNATURE_BYTES         64
#define HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES \
    (HSC_BOX_NONCE_BYTES + HSC_EPHEMERAL_PK_BYTES + HSC_SIGNATURE_BYTES + HSC_BOX_MAC_BYTES)

// Safe upper bound for the size of a decapsulated session key buffer.
#define HSC_MAX_ENCAPSULATED_KEY_SIZE (HSC_SESSION_KEY_BYTES + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES)

// Standard chunk size for file stream processing.
#define HSC_FILE_IO_CHUNK_SIZE 4096

// Special tag marking the final block in a cryptographic stream.
extern const uint8_t HSC_STREAM_TAG_FINAL;

// -----------------------------------------------------------------------------
// Data Structures
// -----------------------------------------------------------------------------

typedef struct hsc_master_key_pair_s hsc_master_key_pair;
typedef struct hsc_crypto_stream_state_s hsc_crypto_stream_state;

typedef struct hsc_pki_config_s {
    // Enables "Private PKI Mode".
    //
    // If true, validation proceeds even if the certificate lacks an AIA/OCSP extension.
    // If false (default), a missing OCSP URI causes validation failure
    // (HSC_ERROR_CERT_NO_OCSP_URI).
    bool allow_no_ocsp_uri;
} hsc_pki_config;

// -----------------------------------------------------------------------------
// Core API: Initialization and Key Management
// -----------------------------------------------------------------------------

// Initializes the Oracipher Core library.
//
// This function must be called once before any other library functions.
//
// config:     Pointer to a configuration structure. If NULL, strictly secure
//             defaults are used (allow_no_ocsp_uri = false).
// pepper_hex: Optional 32-byte hex string (64 chars) acting as a global
//             security pepper. If NULL, the library attempts to read the
//             'HSC_PEPPER_HEX' environment variable.
//
// Returns HSC_OK on success, or an error code on failure.
int hsc_init(const hsc_pki_config* config, const char* pepper_hex);

void hsc_cleanup();

void hsc_random_bytes(void* buf, size_t size);

hsc_master_key_pair* hsc_generate_master_key_pair();

hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(const char* priv_key_path);

int hsc_save_master_key_pair(const hsc_master_key_pair* kp,
                             const char* pub_key_path,
                             const char* priv_key_path);

void hsc_free_master_key_pair(hsc_master_key_pair** kp);

int hsc_get_master_public_key(const hsc_master_key_pair* kp,
                              unsigned char* public_key_out);

// -----------------------------------------------------------------------------
// Core API: PKI and Certificates
// -----------------------------------------------------------------------------

int hsc_generate_csr(const hsc_master_key_pair* mkp,
                     const char* username,
                     char** out_csr_pem);

void hsc_free_pem_string(char* pem_string);

int hsc_verify_user_certificate(const char* user_cert_pem,
                                const char* trusted_ca_cert_pem,
                                const char* expected_username);

int hsc_extract_public_key_from_cert(const char* user_cert_pem,
                                     unsigned char* public_key_out);

// -----------------------------------------------------------------------------
// Core API: Authenticated Key Encapsulation (KEM)
// -----------------------------------------------------------------------------

// Encapsulates a session key using Authenticated Ephemeral KEM.
//
// Generates a ciphertext containing the session key. The output includes a
// signature generated by the sender's master key to bind the sender's identity
// and ensure resistance to sender key compromise.
//
// encrypted_output:    Buffer to receive the encapsulated key.
// encrypted_output_len: Pointer to store the length of the output.
// session_key:         The session key to encapsulate.
// session_key_len:     Length of the session key.
// recipient_pk:        The recipient's public key.
// sender_mkp:          The sender's master key pair (used for signing). Must not be NULL.
int hsc_encapsulate_session_key(unsigned char* encrypted_output,
                                size_t* encrypted_output_len,
                                const unsigned char* session_key, size_t session_key_len,
                                const unsigned char* recipient_pk,
                                const hsc_master_key_pair* sender_mkp);

// Decapsulates a session key using Authenticated Ephemeral KEM.
//
// Decrypts the session key and verifies the sender's signature. If the signature
// is invalid or does not match the provided sender public key, the operation fails.
//
// decrypted_output:    Buffer to receive the raw session key.
// encrypted_input:     The ciphertext to decapsulate.
// encrypted_input_len: Length of the ciphertext.
// recipient_kp:        The recipient's master key pair (used for decryption).
// sender_public_key:   The sender's public key (used for signature verification). Must not be NULL.
int hsc_decapsulate_session_key(unsigned char* decrypted_output,
                                const unsigned char* encrypted_input, size_t encrypted_input_len,
                                const hsc_master_key_pair* recipient_kp,
                                const unsigned char* sender_public_key);

// -----------------------------------------------------------------------------
// Core API: Stream Encryption (Large Files)
// -----------------------------------------------------------------------------

hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(unsigned char* header,
                                                          const unsigned char* key);

hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(const unsigned char* header,
                                                          const unsigned char* key);

void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state);

int hsc_crypto_stream_push(hsc_crypto_stream_state* state,
                           unsigned char* out, unsigned long long* out_len,
                           const unsigned char* in, size_t in_len,
                           uint8_t tag);

int hsc_crypto_stream_pull(hsc_crypto_stream_state* state,
                           unsigned char* out, unsigned long long* out_len,
                           unsigned char* tag,
                           const unsigned char* in, size_t in_len);

// -----------------------------------------------------------------------------
// Core API: Hybrid Encryption (Raw Key Mode)
// -----------------------------------------------------------------------------

// Performs hybrid stream encryption with sender authentication.
int hsc_hybrid_encrypt_stream_raw(const char* output_path,
                                  const char* input_path,
                                  const unsigned char* recipient_pk,
                                  const hsc_master_key_pair* sender_mkp);

// Performs hybrid stream decryption with sender authentication.
int hsc_hybrid_decrypt_stream_raw(const char* output_path,
                                  const char* input_path,
                                  const hsc_master_key_pair* recipient_kp,
                                  const unsigned char* sender_pk);

// -----------------------------------------------------------------------------
// Core API: Single-shot AEAD (Small Data)
// -----------------------------------------------------------------------------

int hsc_aead_encrypt(unsigned char* ciphertext, unsigned long long* ciphertext_len,
                     const unsigned char* message, size_t message_len,
                     const unsigned char* key);

int hsc_aead_decrypt(unsigned char* decrypted_message, unsigned long long* decrypted_message_len,
                     const unsigned char* ciphertext, size_t ciphertext_len,
                     const unsigned char* key);

// -----------------------------------------------------------------------------
// Core API: Secure Memory and Logging
// -----------------------------------------------------------------------------

void* hsc_secure_alloc(size_t size);
void hsc_secure_free(void* ptr);

typedef void (*hsc_log_callback)(int level, const char* message);
void hsc_set_log_callback(hsc_log_callback callback);

// -----------------------------------------------------------------------------
// Expert Level APIs
// -----------------------------------------------------------------------------

// Derives a key from a password and salt using a secure KDF.
//
// derived_key:     Buffer to store the derived key.
// derived_key_len: Desired length of the derived key.
// password:        The input password string.
// salt:            Cryptographic salt.
int hsc_derive_key_from_password(unsigned char* derived_key, size_t derived_key_len,
                                 const char* password, const unsigned char* salt);

// Converts an Ed25519 public key (signing) to an X25519 public key (key exchange).
int hsc_convert_ed25519_pk_to_x25519_pk(unsigned char* x25519_pk_out,
                                        const unsigned char* ed25519_pk_in);

// Converts an Ed25519 private key (signing) to an X25519 private key (key exchange).
int hsc_convert_ed25519_sk_to_x25519_sk(unsigned char* x25519_sk_out,
                                        const unsigned char* ed25519_sk_in);

// Encrypts data using AEAD (XChaCha20-Poly1305) in detached mode.
//
// This is the recommended expert mode for authenticated encryption.
//
// ciphertext:      Buffer for the encrypted data.
// tag_out:         Buffer for the authentication tag.
// nonce_out:       Buffer for the generated nonce.
// message:         Input message to encrypt.
// additional_data: Optional data to authenticate but not encrypt.
// key:             Encryption key.
int hsc_aead_encrypt_detached_safe(unsigned char* ciphertext,
                                   unsigned char* tag_out,
                                   unsigned char* nonce_out,
                                   const unsigned char* message, size_t message_len,
                                   const unsigned char* additional_data, size_t ad_len,
                                   const unsigned char* key);

// Decrypts data using AEAD (XChaCha20-Poly1305) in detached mode.
int hsc_aead_decrypt_detached(unsigned char* decrypted_message,
                              const unsigned char* ciphertext, size_t ciphertext_len,
                              const unsigned char* tag,
                              const unsigned char* additional_data, size_t ad_len,
                              const unsigned char* nonce, const unsigned char* key);

#endif // HSC_KERNEL_H