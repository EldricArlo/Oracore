/**
 * @file security_spec.h
 * @brief 定义项目的核心密码学规范和安全基线。
 *
 * @details
 * 本文件是整个项目的“安全宪法”。它集中定义了所有密码学算法的选择、
 * 密钥长度、以及关键安全参数（如 Argon2id 的最小计算强度）。
 * 任何与密码学相关的常量都应在此处定义，以便于审计和未来的升级。
 */

#ifndef SECURITY_SPEC_H
#define SECURITY_SPEC_H

#include <sodium.h> // 确保可以访问 libsodium 的常量

// =============================================================================
// --- 核心设计原则: 强制的最小安全基线 ---
// =============================================================================

/**
 * @name Argon2id 安全基线 (Argon2id Security Baseline)
 * @brief 规范 3.1: 抗降级攻击 - 内置的最小 Argon2id 安全参数基线。
 *
 * @details
 * 这些值是不可降低的绝对最小值，旨在防止服务器被欺骗以使用不安全的参数。
 * 它们应根据当前的行业最佳实践（如 OWASP 建议）定期审查和更新。
 * 此处选定的值基于 libsodium 的 `crypto_pwhash_OPSLIMIT_MODERATE` 和
 * `crypto_pwhash_MEMLIMIT_MODERATE` 建议，代表了在交互式场景下
 * 的一个良好平衡点。
 */
///@{
#define BASELINE_ARGON2ID_OPSLIMIT 8        ///< Argon2id 的最小迭代次数 (ops limit)。
#define BASELINE_ARGON2ID_MEMLIMIT 268435456 ///< Argon2id 的最小内存使用量 (256 MB)。
///@}


// =============================================================================
// --- 运行时安全参数 (Runtime Security Parameters) ---
// =============================================================================

/**
 * @brief 运行时实际使用的 Argon2id 操作限制。
 * @details 在程序启动时通过 `crypto_config_load_from_env()` 初始化为
 *          `BASELINE_ARGON2ID_OPSLIMIT`，但可以被环境变量覆盖（只能调高）。
 */
extern unsigned long long g_argon2_opslimit;

/**
 * @brief 运行时实际使用的 Argon2id 内存限制。
 * @details 在程序启动时通过 `crypto_config_load_from_env()` 初始化为
 *          `BASELINE_ARGON2ID_MEMLIMIT`，但可以被环境变量覆盖（只能调高）。
 */
extern size_t g_argon2_memlimit;


// =============================================================================
// --- 密码学原语尺寸定义 (Cryptographic Primitive Sizes) ---
// =============================================================================

/**
 * @name 主密钥对尺寸 (Master Key Pair Sizes)
 * @details
 * 主密钥对基于 Ed25519 签名算法。这是一个现代的椭圆曲线签名方案，具有高安全性和高性能。
 * Ed25519 密钥对的一个关键优势是，它可以安全地转换为 X25519 密钥对，
 * 从而用同一对主密钥同时满足数字签名（身份验证）和密钥封装（加密）的需求。
 */
///@{
#define MASTER_PUBLIC_KEY_BYTES crypto_sign_PUBLICKEYBYTES ///< Ed25519 公钥长度 (32字节)。
#define MASTER_SECRET_KEY_BYTES crypto_sign_SECRETKEYBYTES ///< Ed25519 私钥长度 (64字节)。
///@}

/**
 * @brief KDF (Argon2id) 使用的盐值长度。
 */
#define USER_SALT_BYTES crypto_pwhash_SALTBYTES

/**
 * @brief 恢复密钥的长度 (256位)。
 * @details 256位的熵足以抵御当前和可预见未来的暴力破解攻击。
 */
#define RECOVERY_KEY_BYTES 32

/**
 * @brief 对称加密会话密钥的长度。
 * @details 基于 XChaCha20-Poly1305 AEAD 算法。XChaCha20 使用扩展的 192位 Nonce，
 *          使其在随机生成 Nonce 的场景下比标准 ChaCha20 更为安全，几乎不可能发生 Nonce 碰撞。
 */
#define SESSION_KEY_BYTES crypto_aead_xchacha20poly1305_ietf_KEYBYTES

#endif // SECURITY_SPEC_H