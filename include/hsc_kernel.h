#ifndef HSC_KERNEL_H
#define HSC_KERNEL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

// --- [委员会修复] 全局API返回码体系 ---
#define HSC_OK                                     0 // 操作成功
#define HSC_ERROR_GENERAL                         -1 // 未指定的常规错误
#define HSC_ERROR_ALLOCATION_FAILED               -2 // 内存分配失败 (包括安全内存)
#define HSC_ERROR_INVALID_ARGUMENT                -3 // 提供给函数的参数无效
#define HSC_ERROR_FILE_IO                         -4 // 文件读写操作失败
#define HSC_ERROR_CRYPTO_OPERATION                -5 // 底层密码学操作失败 (Libsodium)
#define HSC_ERROR_PKI_OPERATION                   -6 // 底层PKI操作失败 (OpenSSL/Libcurl)
#define HSC_ERROR_INVALID_FORMAT                  -7 // 输入数据格式无效 (例如，无效的PEM证书)

// -- 证书验证专用错误码 --
#define HSC_ERROR_CERT_CHAIN_OR_VALIDITY         -10 // 证书链验证失败或证书已过期/尚未生效
#define HSC_ERROR_CERT_SUBJECT_MISMATCH          -11 // 证书的主体(Common Name)与预期不符
#define HSC_ERROR_CERT_REVOKED_OR_OCSP_FAILED    -12 // 证书已被吊销，或OCSP检查失败 (遵循"故障关闭"原则)


// --- [DEPRECATED] 旧版证书验证返回码 (为保持向后兼容性) ---
#define HSC_VERIFY_SUCCESS HSC_OK
#define HSC_VERIFY_ERROR_GENERAL HSC_ERROR_GENERAL
#define HSC_VERIFY_ERROR_CHAIN_OR_VALIDITY HSC_ERROR_CERT_CHAIN_OR_VALIDITY
#define HSC_VERIFY_ERROR_SUBJECT_MISMATCH HSC_ERROR_CERT_SUBJECT_MISMATCH
#define HSC_VERIFY_ERROR_REVOKED_OR_OCSP_FAILED HSC_ERROR_CERT_REVOKED_OR_OCSP_FAILED


// --- 公共常量 ---
#define HSC_MASTER_PUBLIC_KEY_BYTES 32
#define HSC_MASTER_SECRET_KEY_BYTES 64
#define HSC_SESSION_KEY_BYTES       32

// 流式加密 (XChaCha20-Poly1305 SecretStream) 相关常量
#define HSC_STREAM_HEADER_BYTES 24
#define HSC_STREAM_TAG_BYTES      16 // The size of the authentication tag
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

// 为文件流式处理定义的标准块大小
#define HSC_FILE_IO_CHUNK_SIZE 4096

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