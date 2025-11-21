#ifndef HSC_KERNEL_H
#define HSC_KERNEL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

// --- 全局API返回码体系 ---
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
#define HSC_ERROR_CERT_REVOKED                   -12 // 证书已被其颁发机构明确吊销
#define HSC_ERROR_CERT_OCSP_UNAVAILABLE          -13 // OCSP检查因网络或服务器问题失败 (遵循"故障关闭"原则)
#define HSC_ERROR_CERT_OCSP_STATUS_UNKNOWN       -14 // OCSP服务器报告该证书状态未知 (根据策略视为吊销)
#define HSC_ERROR_CERT_NO_OCSP_URI               -15 // 证书缺少AIA/OCSP扩展，无法进行吊销检查 (Fail-Closed)


// --- 旧版证书验证返回码 (为保持向后兼容性) ---
#define HSC_VERIFY_SUCCESS HSC_OK
#define HSC_VERIFY_ERROR_GENERAL HSC_ERROR_GENERAL
#define HSC_VERIFY_ERROR_CHAIN_OR_VALIDITY HSC_ERROR_CERT_CHAIN_OR_VALIDITY
#define HSC_VERIFY_ERROR_SUBJECT_MISMATCH HSC_ERROR_CERT_SUBJECT_MISMATCH
#define HSC_VERIFY_ERROR_REVOKED HSC_ERROR_CERT_REVOKED
#define HSC_VERIFY_ERROR_OCSP_UNAVAILABLE HSC_ERROR_CERT_OCSP_UNAVAILABLE
#define HSC_VERIFY_ERROR_OCSP_STATUS_UNKNOWN HSC_ERROR_CERT_OCSP_STATUS_UNKNOWN 
#define HSC_VERIFY_ERROR_REVOKED_OR_OCSP_FAILED HSC_ERROR_CERT_OCSP_UNAVAILABLE


// --- 公共常量 ---
#define HSC_MASTER_PUBLIC_KEY_BYTES 32
#define HSC_MASTER_SECRET_KEY_BYTES 64
#define HSC_SESSION_KEY_BYTES       32
#define HSC_KDF_SALT_BYTES          32 // 为新的KDF函数提供一个标准的盐长度

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
#define HSC_MAX_ENCAPSULATED_KEY_SIZE (HSC_SESSION_KEY_BYTES + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES)


// 为文件流式处理定义的标准块大小
#define HSC_FILE_IO_CHUNK_SIZE 4096

// 流式加密中用于标记最后一个数据块的特殊标签
extern const uint8_t HSC_STREAM_TAG_FINAL;


// --- 公共数据结构 ---
typedef struct hsc_master_key_pair_s hsc_master_key_pair;
typedef struct hsc_crypto_stream_state_s hsc_crypto_stream_state;

typedef struct hsc_pki_config_s {
    /**
     * @brief 允许"私有PKI模式" (Private PKI Mode)。
     *        如果设置为 true，当证书缺少 OCSP URI (AIA扩展) 时，验证将不会失败。
     *        默认 (false): 严格模式。如果证书没有 OCSP URI，视为验证失败 (HSC_ERROR_CERT_NO_OCSP_URI)。
     */
    bool allow_no_ocsp_uri;
} hsc_pki_config;


// --- 核心API函数：初始化与密钥管理 ---

/**
 * @brief 初始化 Oracipher Core 库。
 *        必须在任何其他库函数之前调用。
 * 
 * [FIX]: 增加了 pepper_hex 参数以修复 Finding #1。
 *        现在允许调用者显式传递 Pepper，从而避免依赖不安全的环境变量。
 * 
 * @param config 指向配置结构体的指针。
 *               如果传入 NULL，将使用最严格的默认安全配置 (allow_no_ocsp_uri = false)。
 * @param pepper_hex (可选) 全局安全胡椒 (32字节的十六进制字符串，共64字符)。
 *                   如果传入 NULL，库将尝试回退读取环境变量 `HSC_PEPPER_HEX`。
 *                   警告：为了安全性，强烈建议显式传入并在使用后由调用者立即擦除，
 *                   而不是依赖可能残留的环境变量。
 * 
 * @return 成功返回 HSC_OK，失败返回错误码。
 */
int hsc_init(const hsc_pki_config* config, const char* pepper_hex);

void hsc_cleanup();
void hsc_random_bytes(void* buf, size_t size);
hsc_master_key_pair* hsc_generate_master_key_pair();
hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(const char* priv_key_path);
int hsc_save_master_key_pair(const hsc_master_key_pair* kp, const char* pub_key_path, const char* priv_key_path);
void hsc_free_master_key_pair(hsc_master_key_pair** kp);
int hsc_get_master_public_key(const hsc_master_key_pair* kp, unsigned char* public_key_out);

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

// --- 核心API函数：高级混合加解密 (原始密钥模式) ---
int hsc_hybrid_encrypt_stream_raw(const char* output_path,
                                    const char* input_path,
                                    const unsigned char* recipient_pk,
                                    const hsc_master_key_pair* sender_kp);
int hsc_hybrid_decrypt_stream_raw(const char* output_path,
                                    const char* input_path,
                                    const unsigned char* sender_pk,
                                    const hsc_master_key_pair* recipient_kp);


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

// --- 核心API函数：日志回调管理 ---
typedef void (*hsc_log_callback)(int level, const char* message);
void hsc_set_log_callback(hsc_log_callback callback);


// =======================================================================
// --- 专家级API (EXPERT-LEVEL APIS) ---
// 警告：以下函数为高级用户设计，需要调用者对密码学概念有深入理解。
//      不当使用这些函数可能导致严重的安全漏洞。
// =======================================================================

/**
 * @brief [专家级] 从用户密码和盐安全地派生密钥。
 *        此函数使用库内部配置的、经过安全基线验证的 Argon2id 参数。
 *        它会自动处理内部的全局胡椒，用户无需也无法干预此过程。
 * @param derived_key (输出) 存储派生密钥的缓冲区。
 * @param derived_key_len 期望派生的密钥长度。
 * @param password 用户提供的密码字符串。
 * @param salt 一个唯一的、针对此密码的盐值 (建议使用 hsc_random_bytes 生成，
 *             长度应为 HSC_KDF_SALT_BYTES)。
 * @return 成功返回 HSC_OK，失败返回相应的错误码。
 */
int hsc_derive_key_from_password(unsigned char* derived_key, size_t derived_key_len,
                                   const char* password, const unsigned char* salt);

/**
 * @brief [专家级] 将一个Ed25519公钥 (用于签名) 转换为X25519公钥 (用于密钥交换)。
 * @param x25519_pk_out (输出) 存储转换后X25519公钥的缓冲区。
 *                      大小必须为 32 字节 (crypto_box_PUBLICKEYBYTES)。
 * @param ed25519_pk_in (输入) 原始的Ed25519公钥。
 *                      大小必须为 32 字节 (crypto_sign_PUBLICKEYBYTES)。
 * @return 成功返回 HSC_OK，如果转换失败则返回 HSC_ERROR_CRYPTO_OPERATION。
 */
int hsc_convert_ed25519_pk_to_x25519_pk(unsigned char* x25519_pk_out, const unsigned char* ed25519_pk_in);

/**
 * @brief [专家级] 将一个Ed25519私钥 (用于签名) 转换为X25519私钥 (用于密钥交换)。
 * @param x25519_sk_out (输出) 存储转换后X25519私钥的缓冲区。
 *                      **警告**: 此密钥为敏感数据，建议存储在安全内存中，并在用后立即擦除。
 *                      大小必须为 32 字节 (crypto_box_SECRETKEYBYTES)。
 * @param ed25519_sk_in (输入) 原始的Ed25519私钥。
 *                      大小必须为 64 字节 (crypto_sign_SECRETKEYBYTES)。
 * @return 成功返回 HSC_OK，如果转换失败则返回 HSC_ERROR_CRYPTO_OPERATION。
 */
int hsc_convert_ed25519_sk_to_x25519_sk(unsigned char* x25519_sk_out, const unsigned char* ed25519_sk_in);

/**
 * @brief [专家级] [推荐] [分离模式] 安全地使用AEAD (XChaCha20-Poly1305) 对称加密数据。
 *        此版本在内部安全地生成一个唯一的Nonce，并将其与密文分开返回，从根本上避免了Nonce重用风险。
 * 
 * @param ciphertext (输出) 加密后的数据缓冲区 (仅包含纯密文)。
 * @param tag_out (输出) 生成的16字节认证标签 (HSC_AEAD_TAG_BYTES)。
 * @param nonce_out (输出) 存储由函数内部生成的24字节唯一Nonce的缓冲区 (HSC_AEAD_NONCE_BYTES)。
 * @param message 要加密的明文。
 * @param message_len 明文的长度。
 * @param additional_data (可选) 附加验证数据 (AD)，如果不需要则为 NULL。
 * @param ad_len 附加数据的长度，如果 AD 为 NULL 则为 0。
 * @param key 加密密钥 (HSC_SESSION_KEY_BYTES)。
 * @return 成功返回 HSC_OK，失败返回 HSC_ERROR_CRYPTO_OPERATION。
 */
int hsc_aead_encrypt_detached_safe(unsigned char* ciphertext, unsigned char* tag_out, unsigned char* nonce_out,
                                   const unsigned char* message, size_t message_len,
                                   const unsigned char* additional_data, size_t ad_len,
                                   const unsigned char* key);


/**
 * @brief [专家级] [分离模式] 使用AEAD (XChaCha20-Poly1305) 对称解密数据。
 * @param decrypted_message (输出) 解密后的明文缓冲区。
 * @param ciphertext 要解密的纯密文。
 * @param ciphertext_len 纯密文的长度。
 * @param tag (输入) 与密文关联的16字节认证标签 (HSC_AEAD_TAG_BYTES)。
 * @param additional_data (可选) 附加验证数据 (AD)。
 * @param ad_len 附加数据的长度。
 * @param nonce (输入) 用于加密的24字节Nonce (HSC_AEAD_NONCE_BYTES)。
 * @param key 解密密钥 (HSC_SESSION_KEY_BYTES)。
 * @return 成功返回 HSC_OK，如果认证失败或解密失败则返回 HSC_ERROR_CRYPTO_OPERATION。
 */
int hsc_aead_decrypt_detached(unsigned char* decrypted_message,
                              const unsigned char* ciphertext, size_t ciphertext_len,
                              const unsigned char* tag,
                              const unsigned char* additional_data, size_t ad_len,
                              const unsigned char* nonce, const unsigned char* key);


#endif // HSC_KERNEL_H