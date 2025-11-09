#ifndef HSC_KERNEL_H
#define HSC_KERNEL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

// --- 公共常量 ---
#define HSC_MASTER_PUBLIC_KEY_BYTES 32
#define HSC_MASTER_SECRET_KEY_BYTES 64
#define HSC_SESSION_KEY_BYTES       32

// 流式加密 (XChaCha20-Poly1305 SecretStream) 相关常量
#define HSC_STREAM_HEADER_BYTES 24
#define HSC_STREAM_TAG_BYTES      16 // The size of the authentication tag
// 将 Hsc_... 修改为 HSC_...
#define HSC_STREAM_CHUNK_OVERHEAD (HSC_STREAM_TAG_BYTES)

// 为单次 AEAD 加密提供的开销常量
#define HSC_AEAD_NONCE_BYTES    24
#define HSC_AEAD_TAG_BYTES      16
#define HSC_AEAD_OVERHEAD_BYTES (HSC_AEAD_NONCE_BYTES + HSC_AEAD_TAG_BYTES)

// 为密钥封装提供的开销常量
#define HSC_BOX_NONCE_BYTES     24
#define HSC_BOX_MAC_BYTES       16
#define HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES (HSC_BOX_NONCE_BYTES + HSC_BOX_MAC_BYTES)

// 为解封装的会话密钥长度提供一个安全、合理的上限
#define HSC_MAX_ENCAPSULATED_KEY_SIZE (HSC_SESSION_KEY_BYTES + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES + 16)


// 流式加密中用于标记最后一个数据块的特殊标签
extern const uint8_t HSC_STREAM_TAG_FINAL;


// --- 公共数据结构 ---
typedef struct hsc_master_key_pair_s hsc_master_key_pair;
typedef struct hsc_crypto_stream_state_s hsc_crypto_stream_state;


// --- 核心API函数：初始化与密钥管理 ---
int hsc_init();
void hsc_cleanup();
void hsc_random_bytes(void* buf, size_t size);
hsc_master_key_pair* hsc_generate_master_key_pair();
hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(const char* priv_key_path);
int hsc_save_master_key_pair(const hsc_master_key_pair* kp, const char* pub_key_path, const char* priv_key_path);
void hsc_free_master_key_pair(hsc_master_key_pair** kp);

// --- 核心API函数：PKI 与证书 ---
int hsc_generate_csr(const hsc_master_key_pair* mkp, const char* username, char** out_csr_pem);
void hsc_free_pem_string(char* pem_string);
int hsc_verify_user_certificate(const char* user_cert_pem,
                                const char* trusted_ca_cert_pem,
                                const char* expected_username);
int hsc_extract_public_key_from_cert(const char* user_cert_pem,
                                     unsigned char* public_key_out);

// --- 核心API函数：密钥封装 (非对称) ---
int hsc_encapsulate_session_key(unsigned char* encrypted_output,
                                size_t* encrypted_output_len,
                                const unsigned char* session_key, size_t session_key_len,
                                const unsigned char* recipient_pk,
                                const hsc_master_key_pair* my_kp);
int hsc_decapsulate_session_key(unsigned char* decrypted_output,
                                const unsigned char* encrypted_input, size_t encrypted_input_len,
                                const unsigned char* sender_pk,
                                const hsc_master_key_pair* my_kp);

// --- 核心API函数：流式加解密 (适用于大文件) ---
hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(unsigned char* header, const unsigned char* key);
hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(const unsigned char* header, const unsigned char* key);
void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state);
int hsc_crypto_stream_push(hsc_crypto_stream_state* state, unsigned char* out, unsigned long long* out_len, const unsigned char* in, size_t in_len, uint8_t tag);
int hsc_crypto_stream_pull(hsc_crypto_stream_state* state, unsigned char* out, unsigned long long* out_len, unsigned char* tag, const unsigned char* in, size_t in_len);


// --- 核心API函数：单次对称加解密 (适用于小数据) ---
int hsc_aead_encrypt(unsigned char* ciphertext, unsigned long long* ciphertext_len,
                     const unsigned char* message, size_t message_len,
                     const unsigned char* key);
int hsc_aead_decrypt(unsigned char* decrypted_message, unsigned long long* decrypted_message_len,
                     const unsigned char* ciphertext, size_t ciphertext_len,
                     const unsigned char* key);

// --- 核心API函数：安全内存管理 ---
void* hsc_secure_alloc(size_t size);
void hsc_secure_free(void* ptr);


#endif // HSC_KERNEL_H

