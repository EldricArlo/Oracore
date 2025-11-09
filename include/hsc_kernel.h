/**
 * @file hsc_kernel.h
 * @brief 高安全性混合加密内核库 (High-Security Hybrid Encryption Kernel) 的公共 API。
 * @version 4.2
 *
 * @copyright Copyright (c) 2025
 *
 * @details
 * 这是与内核库交互的唯一头文件。它定义了所有公开的数据结构、常量和函数。
 * 核心设计原则包括：
 * 1.  **接口统一**: 所有功能通过本文件中的 `hsc_` 前缀函数提供。
 * 2.  **实现隐藏**: 内部状态和数据结构（如密钥对、流状态）通过不透明指针暴露，
 *     确保了API的稳定性和内部实现的高度封装。
 * 3.  **安全默认**: 库的设计旨在提供安全的默认行为和清晰的错误处理。
 */

#ifndef HSC_KERNEL_H
#define HSC_KERNEL_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

// =============================================================================
// --- 公共常量 (Public Constants) ---
// =============================================================================

/** @name 密钥长度常量 (Key Length Constants) */
///@{
#define HSC_MASTER_PUBLIC_KEY_BYTES 32 ///< Ed25519 主公钥的字节长度。
#define HSC_MASTER_SECRET_KEY_BYTES 64 ///< Ed25519 主私钥的字节长度。
#define HSC_SESSION_KEY_BYTES       32 ///< XChaCha20 对称会话密钥的字节长度。
///@}

/** @name 流式加密常量 (Streaming Encryption Constants - XChaCha20-Poly1305 SecretStream) */
///@{
#define HSC_STREAM_HEADER_BYTES 24      ///< 流加密的头部数据长度。
#define HSC_STREAM_TAG_BYTES    16      ///< 每个数据块附加的认证标签长度。
#define HSC_STREAM_CHUNK_OVERHEAD (HSC_STREAM_TAG_BYTES) ///< 每个加密数据块比原始数据块增加的开销。
///@}

/** @name 单次 AEAD 加密常量 (Single-Shot AEAD Constants) */
///@{
#define HSC_AEAD_NONCE_BYTES    24      ///< AEAD 加密中 Nonce (一次性随机数) 的长度。
#define HSC_AEAD_TAG_BYTES      16      ///< AEAD 加密中认证标签的长度。
#define HSC_AEAD_OVERHEAD_BYTES (HSC_AEAD_NONCE_BYTES + HSC_AEAD_TAG_BYTES) ///< AEAD 加密总开销。密文长度 = 明文长度 + 此开销。
///@}

/** @name 密钥封装常量 (Key Encapsulation Constants) */
///@{
#define HSC_BOX_NONCE_BYTES     24      ///< 密钥封装 (crypto_box) 中 Nonce 的长度。
#define HSC_BOX_MAC_BYTES       16      ///< 密钥封装 (crypto_box) 中认证标签的长度。
#define HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES (HSC_BOX_NONCE_BYTES + HSC_BOX_MAC_BYTES) ///< 密钥封装总开销。
///@}

/**
 * @def HSC_MAX_ENCAPSULATED_KEY_SIZE
 * @brief 定义一个用于解封装的会话密钥长度的安全上限。
 * @details
 * 这用于在解密前分配缓冲区并检查传入数据的长度，防止潜在的整数溢出或恶意长度值导致的缓冲区溢出。
 * 它比理论上的最大值稍大，以提供安全边际。
 */
#define HSC_MAX_ENCAPSULATED_KEY_SIZE (HSC_SESSION_KEY_BYTES + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES + 16)

/**
 * @brief 流式加密中用于标记最后一个数据块的特殊标签。
 * @details 在调用 hsc_crypto_stream_push() 时，将此标签用于最后一个数据块，
 *          以正确终止加密流并确保其可解密。
 */
extern const uint8_t HSC_STREAM_TAG_FINAL;


// =============================================================================
// --- 公共数据结构 (Opaque Data Structures) ---
// =============================================================================

/**
 * @brief 代表一个主密钥对（公钥和私钥）的不透明结构体。
 * @details
 * 内部实现被隐藏。请使用 `hsc_generate_master_key_pair` 创建，
 * 并使用 `hsc_free_master_key_pair` 释放。
 */
typedef struct hsc_master_key_pair_s hsc_master_key_pair;

/**
 * @brief 维护流式加密/解密会话状态的不透明结构体。
 * @details
 * 内部实现被隐藏。请使用 `hsc_crypto_stream_state_new_push` (加密) 或
 * `hsc_crypto_stream_state_new_pull` (解密) 创建，并使用
 * `hsc_crypto_stream_state_free` 释放。
 */
typedef struct hsc_crypto_stream_state_s hsc_crypto_stream_state;


// =============================================================================
// --- 核心 API: 初始化与通用功能 ---
// =============================================================================

/**
 * @brief 初始化内核库。
 * @details
 * **必须在调用任何其他 hsc_ 函数之前调用此函数。**
 * 它会安全地初始化底层的密码学库 (libsodium, OpenSSL) 和网络库 (libcurl)。
 * 此函数是线程安全的。
 * @return 成功返回 0，失败返回 -1。
 */
int hsc_init();

/**
 * @brief 清理并释放内核库使用的全局资源。
 * @details
 * **应在程序退出前调用此函数，以确保所有资源被正确释放。**
 */
void hsc_cleanup();

/**
 * @brief 生成密码学安全的随机字节。
 * @param[out] buf 指向用于存储随机字节的缓冲区的指针。
 * @param[in]  size 要生成的随机字节数。
 */
void hsc_random_bytes(void* buf, size_t size);


// =============================================================================
// --- 核心 API: 主密钥管理 (Master Key Management) ---
// =============================================================================

/**
 * @brief 生成一个全新的主密钥对 (Ed25519)。
 * @details
 * 私钥将被分配在受保护的内存中，以防止被交换到磁盘。
 * @return 成功时返回指向新密钥对的指针，失败时返回 NULL。
 *         返回的指针必须使用 hsc_free_master_key_pair() 释放。
 */
hsc_master_key_pair* hsc_generate_master_key_pair();

/**
 * @brief 从一个文件中加载私钥，并派生出对应的公钥。
 * @param[in] priv_key_path 私钥文件的路径。
 * @return 成功时返回指向加载的密钥对的指针，失败（如文件不存在或格式错误）时返回 NULL。
 *         返回的指针必须使用 hsc_free_master_key_pair() 释放。
 */
hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(const char* priv_key_path);

/**
 * @brief 将主密钥对的公钥和私钥分别保存到文件中。
 * @param[in] kp 要保存的密钥对。
 * @param[in] pub_key_path 保存公钥的目标文件路径。
 * @param[in] priv_key_path 保存私钥的目标文件路径。
 * @return 成功返回 0，失败返回 -1。
 */
int hsc_save_master_key_pair(const hsc_master_key_pair* kp, const char* pub_key_path, const char* priv_key_path);

/**
 * @brief 安全地擦除并释放一个主密钥对。
 * @details
 * 此函数会先用零覆盖私钥所在的受保护内存，然后释放所有相关资源。
 * 它还将外部指针设置为 NULL，以防止悬挂指针 (use-after-free) 错误。
 * @param[in,out] kp 指向密钥对指针的指针。函数执行后，*kp 将被设为 NULL。
 */
void hsc_free_master_key_pair(hsc_master_key_pair** kp);


// =============================================================================
// --- 核心 API: PKI 与证书 (PKI & Certificates) ---
// =============================================================================

/**
 * @brief 基于主密钥对生成一个 PEM 格式的证书签名请求 (CSR)。
 * @param[in]  mkp        用于签名的主密钥对。
 * @param[in]  username   要嵌入到 CSR Common Name (CN) 字段的用户名。
 * @param[out] out_csr_pem 指向一个 char 指针的指针。函数成功时会分配内存并存储
 *                        PEM 格式的 CSR 字符串。调用者必须使用 hsc_free_pem_string() 释放。
 * @return 成功返回 0，失败返回 -1。
 */
int hsc_generate_csr(const hsc_master_key_pair* mkp, const char* username, char** out_csr_pem);

/**
 * @brief 释放由 hsc_generate_csr() 分配的 PEM 字符串内存。
 * @param[in] pem_string 指向要释放的字符串的指针。
 */
void hsc_free_pem_string(char* pem_string);

/**
 * @brief 对用户证书执行完整的验证流程。
 * @details
 * 这是一个关键的安全函数，它会检查：
 * 1. 签名链：证书是否由指定的受信任 CA 签署。
 * 2. 有效期：当前时间是否在证书的有效期内。
 * 3. 主题：证书的 Common Name 是否与预期用户名匹配。
 * 4. 吊销状态：通过 OCSP 检查证书是否已被吊销 (采用 Fail-Closed 策略)。
 * @param[in] user_cert_pem       要验证的用户证书 (PEM 格式)。
 * @param[in] trusted_ca_cert_pem 受信任的根 CA 证书 (PEM 格式)。
 * @param[in] expected_username   期望的用户名。
 * @return 0  如果所有验证全部通过。
 * @return -2 如果签名链或有效期验证失败。
 * @return -3 如果证书主体 (用户名) 不匹配。
 * @return -4 如果 OCSP 吊销状态检查失败。
 * @return -1 如果发生其他错误 (如内存分配失败、PEM 解析错误)。
 */
int hsc_verify_user_certificate(const char* user_cert_pem,
                                const char* trusted_ca_cert_pem,
                                const char* expected_username);
/**
 * @brief 从一个 PEM 格式的证书中提取出原始的 Ed25519 公钥字节。
 * @details
 * **安全警告**: 在调用此函数前，应先使用 hsc_verify_user_certificate() 验证证书的有效性。
 * @param[in]  user_cert_pem   用户证书 (PEM 格式)。
 * @param[out] public_key_out  用于存储提取出的公钥的缓冲区。
 *                             其大小必须至少为 HSC_MASTER_PUBLIC_KEY_BYTES。
 * @return 成功返回 0，失败返回 -1 (例如，证书格式错误或公钥类型不是 Ed25519)。
 */
int hsc_extract_public_key_from_cert(const char* user_cert_pem,
                                     unsigned char* public_key_out);


// =============================================================================
// --- 核心 API: 密钥封装 (Asymmetric Key Encapsulation) ---
// =============================================================================

/**
 * @brief 使用混合加密模型封装一个会话密钥（非对称部分）。
 * @details
 * 此函数使用发送者的私钥和接收者的公钥，通过 X25519 密钥交换和认证加密
 * (crypto_box) 来安全地加密一个会话密钥。
 * @param[out]    encrypted_output     用于存储加密结果的缓冲区。其大小必须至少为
 *                                     `session_key_len + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES`。
 * @param[in,out] encrypted_output_len 指向一个变量的指针。输入时，它应包含 `encrypted_output`
 *                                     缓冲区的总大小；输出时，它将被更新为实际加密数据的长度。
 * @param[in]     session_key          要加密的会话密钥。
 * @param[in]     session_key_len      会话密钥的长度。
 * @param[in]     recipient_pk         接收者的 Ed25519 公钥。
 * @param[in]     my_kp                发送者自己的主密钥对。
 * @return 成功返回 0，失败返回 -1。
 */
int hsc_encapsulate_session_key(unsigned char* encrypted_output,
                                size_t* encrypted_output_len,
                                const unsigned char* session_key, size_t session_key_len,
                                const unsigned char* recipient_pk,
                                const hsc_master_key_pair* my_kp);

/**
 * @brief 解封装一个会话密钥。
 * @details
 * 此函数使用接收者的私钥和发送者的公钥来解密并验证之前被封装的会话密钥。
 * @param[out] decrypted_output    用于存储解密后的会话密钥的缓冲区。
 *                                 其大小应等于原始会话密钥的长度。
 * @param[in]  encrypted_input     包含被封装密钥的数据。
 * @param[in]  encrypted_input_len 被封装密钥数据的长度。
 * @param[in]  sender_pk           发送者的 Ed25519 公钥。
 * @param[in]  my_kp               接收者自己的主密钥对。
 * @return 成功返回 0，失败（如认证失败）返回 -1。
 */
int hsc_decapsulate_session_key(unsigned char* decrypted_output,
                                const unsigned char* encrypted_input, size_t encrypted_input_len,
                                const unsigned char* sender_pk,
                                const hsc_master_key_pair* my_kp);


// =============================================================================
// --- 核心 API: 流式对称加解密 (Symmetric Stream Encryption) ---
// =============================================================================

/**
 * @brief 为流式加密创建一个新的状态对象。
 * @param[out] header 用于存储生成的流头部的缓冲区 (大小必须为 HSC_STREAM_HEADER_BYTES)。
 *                    这个头部必须与加密数据一同保存或传输。
 * @param[in]  key    用于加密的会话密钥 (大小为 HSC_SESSION_KEY_BYTES)。
 * @return 成功时返回指向新状态对象的指针，失败时返回 NULL。
 *         返回的指针必须使用 hsc_crypto_stream_state_free() 释放。
 */
hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(unsigned char* header, const unsigned char* key);

/**
 * @brief 为流式解密创建一个新的状态对象。
 * @param[in] header 从加密方接收到的流头部 (大小为 HSC_STREAM_HEADER_BYTES)。
 * @param[in] key    用于解密的会话密钥 (大小为 HSC_SESSION_KEY_BYTES)。
 * @return 成功时返回指向新状态对象的指针，失败（如头部无效）时返回 NULL。
 *         返回的指针必须使用 hsc_crypto_stream_state_free() 释放。
 */
hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(const unsigned char* header, const unsigned char* key);

/**
 * @brief 安全地擦除并释放流式加密/解密的状态对象。
 * @param[in,out] state 指向状态对象指针的指针。函数执行后，*state 将被设为 NULL。
 */
void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state);

/**
 * @brief 加密一个数据块作为流的一部分。
 * @param[in]     state   由 hsc_crypto_stream_state_new_push() 创建的状态对象。
 * @param[out]    out     用于存储加密数据块的缓冲区。大小必须至少为 `in_len + HSC_STREAM_CHUNK_OVERHEAD`。
 * @param[out]    out_len 指向一个变量的指针，用于存储实际输出的加密数据长度。
 * @param[in]     in      要加密的明文数据块。
 * @param[in]     in_len  明文数据块的长度。
 * @param[in]     tag     一个附加标签。对于最后一个数据块，**必须**使用 HSC_STREAM_TAG_FINAL。
 * @return 成功返回 0，失败返回 -1。
 */
int hsc_crypto_stream_push(hsc_crypto_stream_state* state, unsigned char* out, unsigned long long* out_len, const unsigned char* in, size_t in_len, uint8_t tag);

/**
 * @brief 解密一个数据块作为流的一部分。
 * @param[in]     state   由 hsc_crypto_stream_state_new_pull() 创建的状态对象。
 * @param[out]    out     用于存储解密数据块的缓冲区。
 * @param[out]    out_len 指向一个变量的指针，用于存储实际输出的解密数据长度。
 * @param[out]    tag     指向一个变量的指针，用于存储与此数据块关联的标签。
 * @param[in]     in      要解密的加密数据块。
 * @param[in]     in_len  加密数据块的长度。
 * @return 成功返回 0，失败（如认证失败）返回 -1。
 */
int hsc_crypto_stream_pull(hsc_crypto_stream_state* state, unsigned char* out, unsigned long long* out_len, unsigned char* tag, const unsigned char* in, size_t in_len);


// =============================================================================
// --- 核心 API: 单次对称加解密 (Symmetric AEAD) ---
// =============================================================================

/**
 * @brief 使用 AEAD (XChaCha20-Poly1305) 对一小块数据进行认证加密。
 * @details
 * 适用于一次性加密少量数据（如加密后的主密钥）。
 * 输出格式为 [nonce || ciphertext_with_tag]。
 * @param[out]    ciphertext     用于存储加密结果的缓冲区。其大小必须至少为
 *                               `message_len + HSC_AEAD_OVERHEAD_BYTES`。
 * @param[out]    ciphertext_len 指向一个变量的指针，用于存储最终输出的密文总长度。
 * @param[in]     message        要加密的明文。
 * @param[in]     message_len    明文的长度。
 * @param[in]     key            加密密钥 (大小为 HSC_SESSION_KEY_BYTES)。
 * @return 成功返回 0，失败返回 -1。
 */
int hsc_aead_encrypt(unsigned char* ciphertext, unsigned long long* ciphertext_len,
                     const unsigned char* message, size_t message_len,
                     const unsigned char* key);

/**
 * @brief 使用 AEAD (XChaCha20-Poly1305) 解密并验证一小块数据。
 * @param[out]    decrypted_message     用于存储解密后的明文的缓冲区。
 * @param[out]    decrypted_message_len 指向一个变量的指针，用于存储最终输出的明文长度。
 * @param[in]     ciphertext            要解密的密文。
 * @param[in]     ciphertext_len        密文的长度。
 * @param[in]     key                   解密密钥 (大小为 HSC_SESSION_KEY_BYTES)。
 * @return 成功返回 0，失败（如认证失败）返回 -1。
 */
int hsc_aead_decrypt(unsigned char* decrypted_message, unsigned long long* decrypted_message_len,
                     const unsigned char* ciphertext, size_t ciphertext_len,
                     const unsigned char* key);


// =============================================================================
// --- 核心 API: 安全内存管理 (Secure Memory Management) ---
// =============================================================================

/**
 * @brief 分配一块受保护的、不可交换到磁盘的内存。
 * @details
 * 这对于存储密钥等敏感数据至关重要，可以防止它们被写入交换文件或核心转储文件。
 * @param[in] size 要分配的字节数。
 * @return 成功时返回指向受保护内存的指针，失败时返回 NULL。
 */
void* hsc_secure_alloc(size_t size);

/**
 * @brief 安全地擦除并释放一块由 hsc_secure_alloc() 分配的内存。
 * @details
 * 在释放内存前，会先用零覆盖该内存区域。
 * @param[in] ptr 指向要释放的内存的指针。
 */
void hsc_secure_free(void* ptr);


#endif // HSC_KERNEL_H