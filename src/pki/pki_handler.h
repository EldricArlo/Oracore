/**
 * @file pki_handler.h
 * @brief 定义了处理公钥基础设施 (PKI) 相关操作的内部接口。
 *
 * @details
 * 本模块封装了所有与 X.509 证书相关的复杂操作，主要依赖于 OpenSSL 库。
 * 它负责处理证书签名请求 (CSR) 的生成、证书的严格验证（包括 OCSP 吊销检查），
 * 以及从有效证书中提取公钥。
 */

#ifndef PKI_HANDLER_H
#define PKI_HANDLER_H

// 包含此头文件以获取 master_key_pair 的定义，这是生成 CSR 所必需的。
#include "../core_crypto/crypto_client.h"

/**
 * @name 初始化与资源管理 (Initialization & Resource Management)
 */
///@{

/**
 * @brief 初始化 PKI 子系统。
 * @details
 * **必须在使用任何 PKI 功能前调用。**
 * 它主要负责初始化 OpenSSL 和 libcurl 的全局状态。
 * @return 成功返回 0，失败返回 -1。
 */
int pki_init();

/**
 * @brief 释放由 `generate_csr` 分配的 PEM 格式字符串内存。
 * @param[in] csr_pem 指向要释放的 CSR PEM 字符串的指针。
 */
void free_csr_pem(char* csr_pem);

///@}


/**
 * @name 证书生命周期 (Certificate Lifecycle)
 */
///@{

/**
 * @brief 规范 4 - 阶段一 - 4: 生成证书签名请求 (CSR)。
 * @details
 * 此函数使用用户的主私钥来创建一个标准的 X.509 CSR。
 * CSR 中包含了用户的主公钥和身份信息（用户名/Common Name），
 * 可提交给证书颁发机构 (CA) 进行签名。
 *
 * @param[in]  mkp         指向已初始化的主密钥对的指针。
 * @param[in]  username    要嵌入到 CSR 主题 Common Name (CN) 字段中的用户名。
 * @param[out] out_csr_pem (输出) 指向一个 char 指针的指针。函数成功时将分配内存
 *                         并存储 PEM 格式的 CSR 字符串。调用者必须负责
 *                         使用 `free_csr_pem()` 释放这块内存。
 * @return 成功返回 0，失败返回 -1。
 */
int generate_csr(const master_key_pair* mkp, const char* username, char** out_csr_pem);

/**
 * @brief 规范 4 - 阶段三 - 2.b: 【客户端强制验证】执行完整的证书验证流程。
 * @details
 * 这是一个至关重要的安全函数，它严格执行以下检查：
 * 1.  **签名链 (Chain of Trust):** 证书是否由受信任的 CA 签署。
 * 2.  **有效期 (Validity Period):** 当前时间是否在证书的 `notBefore` 和 `notAfter` 之间。
 * 3.  **主体身份 (Subject Identity):** 证书的 Common Name 是否与预期用户名完全匹配。
 * 4.  **吊销状态 (Revocation Status):** 通过 OCSP 实时检查证书是否已被吊销。
 *     此检查采用 **“故障关闭 (Fail-Closed)”** 策略：如果无法从 OCSP 服务器获得
 *     一个明确的“良好”状态响应，验证将失败。
 *
 * @param[in] user_cert_pem       要验证的用户证书 (PEM 格式)。
 * @param[in] trusted_ca_cert_pem 客户端预置的、受信任的系统根 CA 证书 (PEM 格式)。
 * @param[in] expected_username   期望从证书主体中找到的用户名 (Common Name)。
 *
 * @return 0  如果所有验证步骤全部成功。
 * @return -2 如果证书签名链或有效期验证失败。
 * @return -3 如果证书主体 (Username) 不匹配。
 * @return -4 如果证书吊销状态检查失败 (OCSP)。
 * @return -1 如果发生其他一般性错误 (如内存分配、PEM 解析失败)。
 */
int verify_user_certificate(const char* user_cert_pem,
                            const char* trusted_ca_cert_pem,
                            const char* expected_username);

/**
 * @brief 从一个 PEM 格式的用户证书中提取出原始的公钥字节。
 * @details
 * **安全警告**: 在调用此函数前，应先使用 `verify_user_certificate()` 验证证书。
 * 仅从已通过验证的证书中提取公钥才是安全的。
 *
 * @param[in]  user_cert_pem    要从中提取公钥的证书 (PEM 格式)。
 * @param[out] public_key_out   一个缓冲区，用于存储提取出的原始公钥。
 *                              其大小必须至少为 `MASTER_PUBLIC_KEY_BYTES`。
 * @return 成功返回 0，失败返回 -1 (例如，证书格式错误或公钥类型不是 Ed25519)。
 */
int extract_public_key_from_cert(const char* user_cert_pem,
                                 unsigned char* public_key_out);

///@}

#endif // PKI_HANDLER_H