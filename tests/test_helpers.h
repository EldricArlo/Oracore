#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include <stddef.h>

/**
 * @brief 生成一个用于测试的、自签名的根 CA 证书和私钥。
 *
 * @param ca_key_pem (输出) 指向一个 char 指针的指针，用于存储 PEM 格式的 CA 私钥。
 *                   调用者必须负责释放这块内存。
 * @param ca_cert_pem (输出) 指向一个 char 指针的指针，用于存储 PEM 格式的 CA 证书。
 *                    调用者必须负责释放这块内存。
 * @param seed_byte 用于生成确定性密钥的种子字节。使用不同的种子会生成不同的 CA，
 *                  这对于测试信任链至关重要。
 * @return 成功返回 0，失败返回 -1。
 */
int generate_test_ca(char** ca_key_pem, char** ca_cert_pem, unsigned char seed_byte);

/**
 * @brief 使用指定的 CA 签署一个 CSR，生成一个用户证书，并允许控制其有效期。
 *
 * @param user_cert_pem (输出) 指向一个 char 指針的指针，用于存储 PEM 格式的用户证书。
 *                      调用者必须负责释放这块内存。
 * @param csr_pem 要签署的 PEM 格式的 CSR 字符串。
 * @param ca_key_pem 签署所用的 CA 私钥 (PEM 格式)。
 * @param ca_cert_pem 签署所用的 CA 证书 (PEM 格式)。
 * @param not_before_offset_sec 证书生效时间相对于当前时间的偏移量（秒）。
 *                              0 表示立即生效，-3600 表示一小时前生效。
 * @param not_after_offset_sec 证书过期时间相对于当前时间的偏移量（秒）。
 *                             例如 31536000L 表示一年后过期。
 * @return 成功返回 0，失败返回 -1。
 */
int sign_csr_with_ca(char** user_cert_pem, const char* csr_pem,
                     const char* ca_key_pem, const char* ca_cert_pem,
                     long not_before_offset_sec, long not_after_offset_sec);

#endif // TEST_HELPERS_H