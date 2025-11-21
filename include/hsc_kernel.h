/* --- START OF FILE include/hsc_kernel.h --- */

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
#define HSC_ERROR_SIGNATURE_VERIFICATION_FAILED   -8 // [FIX] 新增错误码：发送者签名验证失败

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

// [FIX]: Finding #2 - 修正 KDF 盐值长度以匹配 Libsodium 的 Argon2id 实现 (crypto_pwhash_SALTBYTES)
#define HSC_KDF_SALT_BYTES          16 

// 流式加密 (XChaCha20-Poly1305 SecretStream) 相关常量
#define HSC_STREAM_HEADER_BYTES 24
#define HSC_STREAM_TAG_BYTES      16 // The size of the authentication tag
#define HSC_STREAM_CHUNK_OVERHEAD (HSC_STREAM_TAG_BYTES)

// 为单次 AEAD 加密提供的开销常量
#define HSC_AEAD_NONCE_BYTES    24
#define HSC_AEAD_TAG_BYTES      16
#define HSC_AEAD_OVERHEAD_BYTES (HSC_AEAD_NONCE_BYTES + HSC_AEAD_TAG_BYTES)

// 为密钥封装提供的开销常量
// [FIX]: Audit Finding #1 - 协议层修复
// 新格式: [Nonce (24)] + [Ephemeral_PK (32)] + [Signature (64)] + [MAC (16)]
// 增加了 Signature (64 bytes) 以绑定发送者身份。
#define HSC_BOX_NONCE_BYTES     24
#define HSC_BOX_MAC_BYTES       16
#define HSC_EPHEMERAL_PK_BYTES  32
#define HSC_SIGNATURE_BYTES     64 // [FIX] 新增签名长度常量
#define HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES (HSC_BOX_NONCE_BYTES + HSC_EPHEMERAL_PK_BYTES + HSC_SIGNATURE_BYTES + HSC_BOX_MAC_BYTES)

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

/**
 * @brief [Ephemeral Key] 封装会话密钥 (Authenticated Ephemeral KEM)
 *        
 *        [FIX]: Audit Finding #1 - Sender Authentication
 *        增加了 sender_mkp 参数。
 *        函数现在会生成 [Nonce] || [Ephemeral_PK] || [Signature] || [Ciphertext]。
 *        发送者使用其身份私钥对 (Ephemeral_PK + Recipient_PK + Ciphertext) 进行签名，
 *        确保接收者可以验证数据来源。
 * 
 *        [Term Update]: 之前被称为 PFS (Perfect Forward Secrecy)，更准确的描述是
 *        针对发送方长期密钥泄露的前向安全保护 (Sender Key Compromise Resistance)。
 * 
 * @param sender_mkp [FIX] 发送者的主密钥对（用于身份签名）。不可为 NULL。
 */
int hsc_encapsulate_session_key(unsigned char* encrypted_output,
                                size_t* encrypted_output_len,
                                const unsigned char* session_key, size_t session_key_len,
                                const unsigned char* recipient_pk,
                                const hsc_master_key_pair* sender_mkp); // [FIX] Added sender_mkp

/**
 * @brief [Ephemeral Key] 解封装会话密钥 (Authenticated Ephemeral KEM)
 * 
 *        [FIX]: Audit Finding #1 - Sender Authentication
 *        增加了 sender_public_key 参数。
 *        解密前，必须验证数据包中的 Signature 是否属于 sender_public_key。
 *        如果签名无效，解密将拒绝执行并返回错误。
 * 
 * @param sender_public_key [FIX] 发送者的身份公钥（用于验签）。不可为 NULL。
 */
int hsc_decapsulate_session_key(unsigned char* decrypted_output,
                                const unsigned char* encrypted_input, size_t encrypted_input_len,
                                const hsc_master_key_pair* recipient_kp,
                                const unsigned char* sender_public_key); // [FIX] Added sender_pk

// --- 核心API函数：流式加解密 (适用于大文件) ---
hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(unsigned char* header, const unsigned char* key);
hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(const unsigned char* header, const unsigned char* key);
void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state);
int hsc_crypto_stream_push(hsc_crypto_stream_state* state, unsigned char* out, unsigned long long* out_len, const unsigned char* in, size_t in_len, uint8_t tag);
int hsc_crypto_stream_pull(hsc_crypto_stream_state* state, unsigned char* out, unsigned long long* out_len, unsigned char* tag, const unsigned char* in, size_t in_len);

// --- 核心API函数：高级混合加解密 (原始密钥模式) ---
// [FIX]: 重新引入 sender_mkp 以支持认证加密
int hsc_hybrid_encrypt_stream_raw(const char* output_path,
                                    const char* input_path,
                                    const unsigned char* recipient_pk,
                                    const hsc_master_key_pair* sender_mkp); // [FIX] Added

// [FIX]: 重新引入 sender_pk 以支持认证解密
int hsc_hybrid_decrypt_stream_raw(const char* output_path,
                                    const char* input_path,
                                    const hsc_master_key_pair* recipient_kp,
                                    const unsigned char* sender_pk); // [FIX] Added


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
// =======================================================================

/**
 * @brief [专家级] 从用户密码和盐安全地派生密钥。
 */
int hsc_derive_key_from_password(unsigned char* derived_key, size_t derived_key_len,
                                   const char* password, const unsigned char* salt);

/**
 * @brief [专家级] 将一个Ed25519公钥 (用于签名) 转换为X25519公钥 (用于密钥交换)。
 */
int hsc_convert_ed25519_pk_to_x25519_pk(unsigned char* x25519_pk_out, const unsigned char* ed25519_pk_in);

/**
 * @brief [专家级] 将一个Ed25519私钥 (用于签名) 转换为X25519私钥 (用于密钥交换)。
 */
int hsc_convert_ed25519_sk_to_x25519_sk(unsigned char* x25519_sk_out, const unsigned char* ed25519_sk_in);

/**
 * @brief [专家级] [推荐] [分离模式] 安全地使用AEAD (XChaCha20-Poly1305) 对称加密数据。
 */
int hsc_aead_encrypt_detached_safe(unsigned char* ciphertext, unsigned char* tag_out, unsigned char* nonce_out,
                                   const unsigned char* message, size_t message_len,
                                   const unsigned char* additional_data, size_t ad_len,
                                   const unsigned char* key);


/**
 * @brief [专家级] [分离模式] 使用AEAD (XChaCha20-Poly1305) 对称解密数据。
 */
int hsc_aead_decrypt_detached(unsigned char* decrypted_message,
                              const unsigned char* ciphertext, size_t ciphertext_len,
                              const unsigned char* tag,
                              const unsigned char* additional_data, size_t ad_len,
                              const unsigned char* nonce, const unsigned char* key);


#endif // HSC_KERNEL_H
/* --- END OF FILE include/hsc_kernel.h --- */