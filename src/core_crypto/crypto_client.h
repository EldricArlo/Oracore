#ifndef CRYPTO_CLIENT_H
#define CRYPTO_CLIENT_H

#include "../common/security_spec.h"
#include <stdbool.h>

// --- 数据结构定义 ---

// 主密钥对结构体
typedef struct {
    unsigned char pk[MASTER_PUBLIC_KEY_BYTES];
    // 使用 `secure_alloc` 分配，确保私钥在受保护的内存中
    unsigned char* sk; 
} master_key_pair;

// 恢复密钥结构体 (同样使用受保护内存)
typedef struct {
    unsigned char* key;
} recovery_key;


// --- 函数原型 ---

/**
 * @brief 初始化密码学库，必须在任何密码学操作前调用。
 * @return 成功返回 0，失败返回 -1。
 */
int crypto_client_init();

/**
 * @brief 生成一个全新的主密钥对 (公钥 + 私钥)。
 * @param kp 指向 master_key_pair 结构体的指针，用于存储生成的密钥对。
 * @return 成功返回 0，失败返回 -1。私钥存储在安全内存中。
 */
int generate_master_key_pair(master_key_pair* kp);

/**
 * @brief 释放主密钥对占用的安全内存。
 * @param kp 指向要释放的密钥对结构体。
 */
void free_master_key_pair(master_key_pair* kp);

/**
 * @brief 生成一个全新的恢复密钥。
 * @param rk 指向 recovery_key 结构体的指针，用于存储生成的密钥。
 * @return 成功返回 0，失败返回 -1。密钥存储在安全内存中。
 */
int generate_recovery_key(recovery_key* rk);

/**
 * @brief 释放恢复密钥占用的安全内存。
 * @param rk 指向要释放的恢复密钥结构体。
 */
void free_recovery_key(recovery_key* rk);


/**
 * @brief 规范 3.1: 验证从服务器获取的 Argon2id 参数是否不低于内置的安全基线。
 * @param opslimit 服务器提供的 opslimit 参数。
 * @param memlimit 服务器提供的 memlimit 参数。
 * @return 如果参数安全则返回 true，否则返回 false。
 */
bool validate_argon2id_params(unsigned long long opslimit, size_t memlimit);

/**
 * @brief 从用户密码、盐和胡椒派生出加密密钥。
 *        此函数严格遵循规范，在派生前会校验安全参数。
 *
 * @param derived_key (输出) 指向存储派生密钥的缓冲区的指针。
 * @param derived_key_len 期望的派生密钥长度。
 * @param password 用户输入的密码。
 * @param salt 用户盐值。
 * @param opslimit Argon2id 的操作限制参数。
 * @param memlimit Argon2id 的内存限制参数。
 * @param global_pepper 全局胡椒。
 * @param pepper_len 胡椒的长度。
 * @return 成功返回 0，如果参数校验失败或派生失败则返回 -1。
 */
int derive_key_from_password(
    unsigned char* derived_key, size_t derived_key_len,
    const char* password,
    const unsigned char* salt,
    unsigned long long opslimit, size_t memlimit,
    const unsigned char* global_pepper, size_t pepper_len
);

/**
 * @brief 使用 AEAD (XChaCha20-Poly1305) 对称加密数据。
 *
 * @param ciphertext (输出) 加密后的数据缓冲区。
 * @param ciphertext_len (输出) 加密后数据的长度。
 * @param message 要加密的明文。
 * @param message_len 明文的长度。
 * @param key 加密密钥。
 * @return 成功返回 0，失败返回 -1。
 */
int encrypt_symmetric_aead(
    unsigned char* ciphertext, unsigned long long* ciphertext_len,
    const unsigned char* message, size_t message_len,
    const unsigned char* key
);

/**
 * @brief 使用 AEAD (XChaCha20-Poly1305) 对称解密数据。
 *
 * @param decrypted_message (输出) 解密后的明文缓冲区。
 * @param decrypted_message_len (输出) 解密后明文的长度。
 * @param ciphertext 要解密的密文。
 * @param ciphertext_len 密文的长度。
 * @param key 解密密钥。
 * @return 成功返回 0，失败（如验证失败）返回 -1。
 */
int decrypt_symmetric_aead(
    unsigned char* decrypted_message, unsigned long long* decrypted_message_len,
    const unsigned char* ciphertext, size_t ciphertext_len,
    const unsigned char* key
);


/**
 * @brief 规范 4 - 阶段三 - 4: 【已修复】封装会话密钥 (非对称加密)。
 *        使用我方的私钥和接收者的公钥，加密一个会话密钥。
 *        输出格式为 [nonce || encrypted_key]，其中 nonce 长度为 crypto_box_NONCEBYTES。
 *
 * @param encrypted_output (输出) 存放加密结果的缓冲区。其大小必须至少为
 *                       crypto_box_NONCEBYTES + session_key_len + crypto_box_MACBYTES。
 * @param encrypted_output_len (输出) 指向一个变量的指针，用于存储最终输出的总长度。
 * @param session_key 要加密的会话密钥明文。
 * @param session_key_len 会话密钥的长度。
 * @param recipient_sign_pk 接收者的 Ed25519 主公钥。
 * @param my_sign_sk 我方（发送者）的 Ed25519 主私钥。
 * @return 成功返回 0，失败返回 -1。
 */
int encapsulate_session_key(unsigned char* encrypted_output,
                            size_t* encrypted_output_len,
                            const unsigned char* session_key, size_t session_key_len,
                            const unsigned char* recipient_sign_pk,
                            const unsigned char* my_sign_sk);

/**
 * @brief 解封装会话密钥 (非对称解密)。
 *        使用我方的私钥和发送者的公钥，解密一个会话密钥。
 *        输入数据格式应为 [nonce || encrypted_key]。
 *
 * @param decrypted_output (输出) 存放解密后的会话密钥的缓冲区。
 * @param encrypted_input 要解密的封装数据。
 * @param encrypted_input_len 封装数据的长度。
 * @param sender_sign_pk 发送者的 Ed25519 主公钥。
 * @param my_sign_sk 我方（接收者）的 Ed25519 主私钥。
 * @return 成功返回 0，失败（如验证失败）返回 -1。
 */
int decapsulate_session_key(unsigned char* decrypted_output,
                            const unsigned char* encrypted_input, size_t encrypted_input_len,
                            const unsigned char* sender_sign_pk,
                            const unsigned char* my_sk);


#endif // CRYPTO_CLIENT_H