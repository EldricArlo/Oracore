/**
 * @file crypto_client.h
 * @brief 定义了所有核心密码学操作的内部接口。
 *
 * @details
 * 本文件是密码学功能的内部抽象层，主要作为 libsodium 功能的封装器。
 * 它为上层模块（如 hsc_kernel.c）提供了一套稳定、一致且符合项目安全规范的
 * 密码学原语。所有函数都应处理必要的错误检查并返回明确的状态码。
 */

#ifndef CRYPTO_CLIENT_H
#define CRYPTO_CLIENT_H

#include "../common/security_spec.h"
#include <stdbool.h>

// =============================================================================
// --- 数据结构定义 (Data Structures) ---
// =============================================================================

/**
 * @brief 内部表示一个主密钥对 (Ed25519)。
 */
typedef struct {
    unsigned char pk[MASTER_PUBLIC_KEY_BYTES]; ///< 公钥部分。
    unsigned char* sk; ///< 指向私钥的指针。**必须**使用 `secure_alloc` 分配。
} master_key_pair;

/**
 * @brief 内部表示一个恢复密钥。
 */
typedef struct {
    unsigned char* key; ///< 指向密钥的指针。**必须**使用 `secure_alloc` 分配。
} recovery_key;


// =============================================================================
// --- 函数原型 (Function Prototypes) ---
// =============================================================================

/**
 * @name 初始化与配置 (Initialization & Configuration)
 */
///@{

/**
 * @brief 初始化密码学库 (libsodium)。
 * @details 必须在任何密码学操作前调用。它是线程安全的，可以多次安全调用。
 *          同时，它会调用 crypto_config_load_from_env() 来加载运行时安全参数。
 * @return 成功返回 0，失败返回 -1。
 */
int crypto_client_init();

/**
 * @brief 从环境变量加载并验证密码学参数 (Argon2id)。
 * @details 读取 `HSC_ARGON2_OPSLIMIT` 和 `HSC_ARGON2_MEMLIMIT` 环境变量。
 *          如果设置的值高于内置的安全基线，则使用它们；否则，将保持安全的基线值。
 *          这实现了“抗降级攻击”的设计目标。
 */
void crypto_config_load_from_env();

///@}


/**
 * @name 密钥生成与管理 (Key Generation & Management)
 */
///@{

/**
 * @brief 生成一个全新的主密钥对 (Ed25519)。
 * @param[out] kp 指向 `master_key_pair` 结构体的指针，用于存储生成的密钥对。
 *                其 `sk` 成员将被分配在受保护内存中。
 * @return 成功返回 0，失败（如内存分配失败）返回 -1。
 */
int generate_master_key_pair(master_key_pair* kp);

/**
 * @brief 安全地释放主密钥对占用的内存。
 * @param[in,out] kp 指向要释放的密钥对结构体。函数执行后，其 `sk` 成员会被设为 NULL。
 */
void free_master_key_pair(master_key_pair* kp);

/**
 * @brief 生成一个全新的恢复密钥。
 * @param[out] rk 指向 `recovery_key` 结构体的指针，用于存储生成的密钥。
 *                其 `key` 成员将被分配在受保护内存中。
 * @return 成功返回 0，失败（如内存分配失败）返回 -1。
 */
int generate_recovery_key(recovery_key* rk);

/**
 * @brief 安全地释放恢复密钥占用的内存。
 * @param[in,out] rk 指向要释放的恢复密钥结构体。函数执行后，其 `key` 成员会被设为 NULL。
 */
void free_recovery_key(recovery_key* rk);

///@}


/**
 * @name 密钥派生 (Key Derivation)
 */
///@{

/**
 * @brief 验证 Argon2id 参数是否不低于内置的安全基线。
 * @param[in] opslimit 要验证的 opslimit 参数。
 * @param[in] memlimit 要验证的 memlimit 参数。
 * @return 如果参数安全则返回 true，否则返回 false。
 */
bool validate_argon2id_params(unsigned long long opslimit, size_t memlimit);

/**
 * @brief 从用户密码、盐和胡椒派生出加密密钥 (使用 Argon2id)。
 * @details
 * 此函数严格遵循规范，在派生前会使用 `validate_argon2id_params` 校验安全参数。
 * 它内部实现了 H(pepper || password) 的模式，以安全地整合胡椒。
 *
 * @param[out]    derived_key     指向存储派生密钥的缓冲区的指针。
 * @param[in]     derived_key_len 期望的派生密钥长度。
 * @param[in]     password        用户输入的密码。
 * @param[in]     salt            用户盐值。
 * @param[in]     opslimit        Argon2id 的操作限制参数。
 * @param[in]     memlimit        Argon2id 的内存限制参数。
 * @param[in]     global_pepper   全局胡椒。
 * @param[in]     pepper_len      胡椒的长度。
 * @return 成功返回 0，如果参数校验失败或派生过程失败则返回 -1。
 */
int derive_key_from_password(
    unsigned char* derived_key, size_t derived_key_len,
    const char* password,
    const unsigned char* salt,
    unsigned long long opslimit, size_t memlimit,
    const unsigned char* global_pepper, size_t pepper_len
);

///@}


/**
 * @name 对称加密 (Symmetric Cryptography - AEAD)
 */
///@{

/**
 * @brief 使用 AEAD (XChaCha20-Poly1305) 对称加密数据。
 * @details
 * 输出的密文格式为 `[nonce || 认证加密后的数据]`。Nonce 长度为 `crypto_aead_xchacha20poly1305_ietf_NPUBBYTES`。
 *
 * @param[out]    ciphertext     (输出) 加密后的数据缓冲区。
 * @param[out]    ciphertext_len (输出) 加密后数据的实际总长度。
 * @param[in]     message        要加密的明文。
 * @param[in]     message_len    明文的长度。
 * @param[in]     key            加密密钥。
 * @return 成功返回 0，失败返回 -1。
 */
int encrypt_symmetric_aead(
    unsigned char* ciphertext, unsigned long long* ciphertext_len,
    const unsigned char* message, size_t message_len,
    const unsigned char* key
);

/**
 * @brief 使用 AEAD (XChaCha20-Poly1305) 对称解密数据。
 * @param[out]    decrypted_message     (输出) 解密后的明文缓冲区。
 * @param[out]    decrypted_message_len (输出) 解密后明文的实际长度。
 * @param[in]     ciphertext            要解密的密文，其格式必须为 `[nonce || 认证加密后的数据]`。
 * @param[in]     ciphertext_len        密文的总长度。
 * @param[in]     key                   解密密钥。
 * @return 成功返回 0，失败（如认证标签验证失败）返回 -1。
 */
int decrypt_symmetric_aead(
    unsigned char* decrypted_message, unsigned long long* decrypted_message_len,
    const unsigned char* ciphertext, size_t ciphertext_len,
    const unsigned char* key
);

///@}


/**
 * @name 非对称加密 (Asymmetric Cryptography - Key Encapsulation)
 */
///@{

/**
 * @brief 规范 4 - 阶段三 - 4: 封装会话密钥 (使用 crypto_box)。
 * @details
 * 使用发送者的 Ed25519 私钥和接收者的 Ed25519 公钥，通过 X25519 密钥交换和认证加密
 * 来安全地加密一个会话密钥。输出格式为 `[nonce || 加密后的会话密钥及认证标签]`。
 * Nonce 长度为 `crypto_box_NONCEBYTES`。
 *
 * @param[out]    encrypted_output     (输出) 存放加密结果的缓冲区。其大小必须至少为
 *                                     `session_key_len + HSC_ENCAPSULATED_KEY_OVERHEAD_BYTES`。
 * @param[out]    encrypted_output_len (输出) 指向一个变量的指针，用于存储最终输出的总长度。
 * @param[in]     session_key          要加密的会话密钥明文。
 * @param[in]     session_key_len      会话密钥的长度。
 * @param[in]     recipient_sign_pk    接收者的 Ed25519 主公钥。
 * @param[in]     my_sign_sk           发送者的 Ed25519 主私钥。
 * @return 成功返回 0，失败返回 -1。
 */
int encapsulate_session_key(unsigned char* encrypted_output,
                            size_t* encrypted_output_len,
                            const unsigned char* session_key, size_t session_key_len,
                            const unsigned char* recipient_sign_pk,
                            const unsigned char* my_sign_sk);

/**
 * @brief 解封装会话密钥 (使用 crypto_box_open)。
 * @details
 * 使用接收者的 Ed25519 私钥和发送者的 Ed25519 公钥来解密并验证一个会话密钥。
 *
 * @param[out] decrypted_output    (输出) 存放解密后的会话密钥的缓冲区。
 * @param[in]  encrypted_input     要解密的封装数据，格式必须为 `[nonce || 加密数据]`。
 * @param[in]  encrypted_input_len 封装数据的总长度。
 * @param[in]  sender_sign_pk      发送者的 Ed25519 主公钥。
 * @param[in]  my_sign_sk          接收者的 Ed25519 主私钥。
 * @return 成功返回 0，失败（如认证失败）返回 -1。
 */
int decapsulate_session_key(unsigned char* decrypted_output,
                            const unsigned char* encrypted_input, size_t encrypted_input_len,
                            const unsigned char* sender_sign_pk,
                            const unsigned char* my_sign_sk);

///@}

#endif // CRYPTO_CLIENT_H