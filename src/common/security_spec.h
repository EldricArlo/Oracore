#ifndef SECURITY_SPEC_H
#define SECURITY_SPEC_H

#include <sodium.h> // 引入 libsodium

// --- 核心设计原则: 强制的最小安全基线 ---

// 规范 3.1: 抗降级攻击 - 内置的最小 Argon2id 安全参数基线
// 这些值应根据当前的最佳实践定期审查和更新。
// 使用 crypto_pwhash_OPSLIMIT_MODERATE 和 crypto_pwhash_MEMLIMIT_MODERATE 作为参考
#define MIN_ARGON2ID_OPSLIMIT 8
#define MIN_ARGON2ID_MEMLIMIT 268435456 // 256 MB

// 【已修改】主密钥对现在基于 Ed25519 签名算法 (crypto_sign)。
// 这个密钥对将用于签署 CSR 以证明身份，同时可以被转换为
// X25519 密钥对用于加密操作（密钥封装）。
#define MASTER_PUBLIC_KEY_BYTES crypto_sign_PUBLICKEYBYTES
#define MASTER_SECRET_KEY_BYTES crypto_sign_SECRETKEYBYTES

// 盐值大小
#define USER_SALT_BYTES crypto_pwhash_SALTBYTES

// 恢复密钥大小 (建议使用高熵的随机字节)
#define RECOVERY_KEY_BYTES 32 // 256 bits

// AEAD 会话密钥大小 (用于文件加密)
#define SESSION_KEY_BYTES crypto_aead_xchacha20poly1305_ietf_KEYBYTES

#endif // SECURITY_SPEC_H