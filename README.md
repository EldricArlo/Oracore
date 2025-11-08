
# 高安全性混合加密客户端库 (High-Security Hybrid Encryption Client Library)

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Language](https://img.shields.io/badge/language-C11-purple)
![Libsodium](https://img.shields.io/badge/dependency-libsodium-_31D843)
![OpenSSL](https://img.shields.io/badge/dependency-OpenSSL_3-0075A8)

本项目是一个使用C语言实现的、专注于安全性的高级混合加密客户端库。它演示了如何结合使用行业领先的密码学库（libsodium 和 OpenSSL）来构建一个健壮的、端到端的加密解决方案。该方案集成了对称加密、非对称加密和公钥基础设施（PKI），适用于需要高度保密性和身份认证的应用场景。

## ✨ 核心特性

*   **混合加密模型:** 高效的AEAD对称加密（XChaCha20-Poly1305）用于加密大数据，强大的非对称加密（X25519）用于安全地封装和交换对称密钥。
*   **现代化的密码学原语:**
    *   **密钥派生:** 使用当前推荐的 **Argon2id** 算法从用户密码安全地派生密钥。
    *   **签名与密钥交换:** 使用 **Ed25519** 进行身份签名，并能动态转换为 **X25519** 进行密钥交换，实现了密钥的统一与功能分离。
    *   **对称加密:** **XChaCha20-Poly1305** 提供高安全性的认证加密（AEAD），能抵御篡改并适用于大数据流。
*   **安全的内存管理:** 所有私钥和其他敏感数据（如会话密钥）都存储在使用 `libsodium` 分配的受保护内存中，防止被交换到磁盘或在释放后留下痕迹。
*   **公钥基础设施 (PKI):**
    *   支持生成符合 X.509 标准的**证书签名请求 (CSR)**。
    *   提供严格的**证书验证**链，包括信任链、有效期、主题匹配和（模拟的）吊销状态检查。
*   **模块化与高内聚设计:** 项目结构清晰，分为核心加密、PKI处理和通用安全模块，易于理解、维护和扩展。
*   **健壮的错误处理:** 所有对外暴露的API都进行了严格的参数检查，并返回明确的错误码。
*   **经过测试:** 包含一套完整的单元测试，确保核心加密功能的正确性和可靠性。

## 目录

- [高安全性混合加密客户端库 (High-Security Hybrid Encryption Client Library)](#-高安全性混合加密客户端库-high-security-hybrid-encryption-client-library)
  - [✨ 核心特性](#-核心特性)
  - [目录](#目录)
  - [🚀 快速开始](#-快速开始)
    - [依赖环境](#依赖环境)
    - [编译与运行](#编译与运行)
  - [📂 项目结构](#-项目结构)
  - [🔐 加密逻辑详解](#-加密逻辑详解)
    - [阶段一：身份与密钥体系](#阶段一身份与密钥体系)
    - [阶段二：文件/数据的对称加密 (AEAD)](#阶段二文件数据的对称加密-aead)
    - [阶段三：会话密钥的非对称封装与共享](#阶段三会话密钥的非对称封装与共享)
    - [总结：一个安全的“传输包”](#总结一个安全的传输包)
  - [🛠️ API 参考文档](#️-api-参考文档)
    - [`core_crypto` 模块](#core_crypto-模块)
    - [`pki_handler` 模块](#pki_handler-模块)
    - [`secure_memory` 模块](#secure_memory-模块)
  - [📜 证书说明](#-证书说明)
  - [🤝 贡献](#-贡献)
  - [📄 许可证](#-许可证)

## 🚀 快速开始

### 依赖环境

在编译和运行本项目之前，请确保您的系统上已安装以下软件：

*   **C 编译器:** `gcc` 或 `clang` (支持 C11 标准)
*   **构建工具:** `make`
*   **Libsodium:** 一个现代化且易于使用的密码学库。
*   **OpenSSL:** 用于处理证书和PKI操作 (需要 3.x 版本或更高)。

**在 Debian/Ubuntu 上安装依赖:**
```bash
sudo apt-get update
sudo apt-get install build-essential libsodium-dev libssl-dev
```

**在 macOS 上使用 Homebrew 安装依赖:**
```bash
brew install libsodium openssl
```

### 编译与运行

1.  **克隆仓库:**
    ```bash
    git clone <your-repository-url>
    cd <repository-directory>
    ```

2.  **编译项目:**
    Makefile 提供了简单易用的指令。
    ```bash
    make
    ```
    这将编译所有源文件并生成名为 `high_security_app` 的主程序可执行文件。

3.  **运行单元测试:**
    我们强烈建议在运行主程序前先执行测试，以确保所有加密模块在您的系统上都能正常工作。
    ```bash
    make test
    ```

4.  **运行演示程序:**
    ```bash
    ./high_security_app
    ```
    该程序将完整地演示从生成用户密钥、签发证书，到加密文件、封装密钥，最后再解密恢复文件的整个端到端流程。

5.  **清理构建文件:**
    ```bash
    make clean
    ```

## 📂 项目结构

```
.
├── Makefile              # 构建脚本
├── README.md             # 本文档
├── src                   # 源代码目录
│   ├── common            # 通用模块
│   │   ├── secure_memory.c # 安全内存分配与擦除的实现
│   │   ├── secure_memory.h # 头文件
│   │   └── security_spec.h # 项目的安全参数和常量定义
│   ├── core_crypto       # 核心加密逻辑
│   │   ├── crypto_client.c # 加密、解密、密钥生成、密钥派生等核心功能实现
│   │   └── crypto_client.h # 头文件
│   ├── main.c            # 演示程序入口
│   └── pki               # 公钥基础设施 (PKI) 相关逻辑
│       ├── pki_handler.c   # CSR生成、证书验证等PKI功能实现
│       └── pki_handler.h   # 头文件
└── tests                 # 测试代码目录
    ├── test_core_crypto.c  # 针对 core_crypto 模块的单元测试
    └── test_pki_handler.c  # 针对 pki_handler 模块的单元测试
```

## 🔐 加密逻辑详解

本项目的核心是一个**混合加密系统**。这种设计结合了对称加密的高效率和非对称加密的密钥管理优势。以下是核心流程的分解说明：

### 阶段一：身份与密钥体系

1.  **主密钥对 (Master Key Pair):**
    *   每个用户（例如 "Alice"）首先需要一个身份标识。在我们的系统中，这个身份的核心是一个 **Ed25519** 主密钥对 (`master_key_pair`)。
    *   **Ed25519** 是一个高性能的数字签名算法。公钥 (`pk`) 是公开的，代表用户的身份。私钥 (`sk`) 必须绝对保密，用于签署声明以证明“我是Alice”。
    *   私钥通过 `secure_alloc` 分配在受保护内存中，确保其生命周期内的安全性。

2.  **证书签名请求 (CSR):**
    *   仅有密钥对是不够的，还需要一个受信任的第三方（证书颁发机构, CA）来证明这个公钥确实属于 "Alice"。
    *   用户使用她的主私钥签署一个包含其公钥和身份信息（如用户名）的**证书签名请求 (CSR)**。
    *   这个过程由 `generate_csr` 函数完成，它利用 OpenSSL 创建一个标准的 PKCS#10 CSR。

3.  **获取证书:**
    *   CSR 被发送给 CA。CA 在验证了用户的真实身份后，会用 CA 自己的私钥来签署用户的 CSR，从而生成一个 **X.509 证书**。
    *   这个证书在法律和技术上都将用户的公钥和其身份绑定在了一起。

### 阶段二：文件/数据的对称加密 (AEAD)

假设 Alice 想要加密一个文件，这个文件可能很大。

1.  **生成会话密钥 (Session Key):**
    *   直接使用非对称加密来加密大文件是非常低效的。因此，我们为**每一次加密会话**生成一个一次性的、高熵的**对称会话密钥** (`session_key`)。
    *   这个密钥是一个短暂的、随机的字节序列。

2.  **认证加密 (AEAD):**
    *   使用这个会话密钥和 **XChaCha20-Poly1305** 算法来加密文件内容。
    *   我们选择 AEAD 是因为它不仅提供了**机密性**（防止窃听），还提供了**完整性**和**真实性**（防止数据被篡改）。任何对密文的修改都会在解密时被检测出来，导致解密失败。
    *   此过程由 `encrypt_symmetric_aead` 完成。

### 阶段三：会话密钥的非对称封装与共享

现在，Alice 有了加密后的文件，但她需要一种安全的方式将**会话密钥**发送给接收者 Bob。

1.  **验证接收者身份:**
    *   Alice 首先必须获取 Bob 的**可信公钥**。她从一个可信的目录服务获取 Bob 的 X.509 证书。
    *   她必须严格验证该证书的有效性，通过 `verify_user_certificate` 函数执行以下检查：
        *   **信任链:** 证书是否由一个 Alice 信任的 CA 签署？
        *   **有效期:** 证书是否在当前有效期内？
        *   **主题匹配:** 证书中的身份信息是否与 "Bob" 匹配？
        *   **吊销状态:** (在本项目中为模拟) 证书是否已被吊销？
    *   只有通过所有检查，Alice 才能确信证书中的公钥确实属于 Bob。

2.  **密钥封装 (Key Encapsulation):**
    *   Alice 从 Bob 的证书中提取出他经过验证的 **Ed25519 公钥**。
    *   接下来是本系统最精妙的一步：
        *   Alice 将自己的 **Ed25519 私钥** 动态转换为一个 **X25519 私钥**。
        *   她也将 Bob 的 **Ed25519 公钥** 转换为一个 **X25519 公钥**。
        *   **为什么这样做？** Ed25519 用于签名，而 X25519 (基于同一条曲线 Curve25519) 用于密钥协商和加密。这种转换允许一个密钥对同时服务于签名和加密两种目的，极大地简化了密钥管理。
    *   Alice 现在使用她的 X25519 私钥和 Bob 的 X25519 公钥，通过 `libsodium` 的 `crypto_box` 功能来加密**会话密钥**。
    *   这个过程由 `encapsulate_session_key` 完成。它会生成一个包含**随机Nonce**和加密后会话密钥的密文。

### 总结：一个安全的“传输包”

Alice 最终会向 Bob 发送一个“传输包”，其中包含两样东西：
1.  **加密后的文件** (使用 AEAD 和会话密钥加密)。
2.  **封装后的会话密钥** (使用非对称加密和 Alice/Bob 的主密钥对加密)。

当 Bob 收到后，他会先用自己的主私钥和 Alice 的公钥解封装得到会话密钥，然后再用会话密钥解密文件。整个过程实现了端到端的安全。

## 🛠️ API 参考文档

### `core_crypto` 模块
*头文件: `src/core_crypto/crypto_client.h`*

---
`int crypto_client_init()`
*   **描述:** 初始化密码学库(libsodium)。必须在调用任何其他加密函数之前调用。
*   **返回:** `0` 成功, `-1` 失败。

---
`int generate_master_key_pair(master_key_pair* kp)`
*   **描述:** 生成一个全新的 Ed25519 主密钥对。
*   **@param** `kp` (输出) 指向 `master_key_pair` 结构体的指针，用于存储结果。
*   **返回:** `0` 成功, `-1` 失败。

---
`int encapsulate_session_key(...)`
*   **描述:** 使用发送者的私钥和接收者的公钥，安全地加密一个会话密钥。
*   **@param** `encrypted_output` (输出) 存放加密结果的缓冲区。
*   **@param** `encrypted_output_len` (输出) 指向变量的指针，用于存储最终输出的总长度。
*   **@param** `session_key` 要加密的会话密钥。
*   **@param** `session_key_len` 会话密钥的长度。
*   **@param** `recipient_sign_pk` 接收者的 Ed25519 公钥。
*   **@param** `my_sign_sk` 发送者的 Ed25519 私钥。
*   **返回:** `0` 成功, `-1` 失败。

---
*(其他 `core_crypto` 函数如 `free_master_key_pair`, `generate_recovery_key`, `derive_key_from_password`, `encrypt_symmetric_aead`, `decapsulate_session_key` 等，请参考头文件中的详细注释。)*

### `pki_handler` 模块
*头文件: `src/pki/pki_handler.h`*

---
`int pki_init()`
*   **描述:** 初始化PKI子系统 (加载 OpenSSL provider)。
*   **返回:** `0` 成功, `-1` 失败。

---
`int generate_csr(const master_key_pair* mkp, const char* username, char** out_csr_pem)`
*   **描述:** 使用主密钥对为指定用户名生成一个 PEM 格式的证书签名请求。
*   **@param** `mkp` 指向已初始化的主密钥对。
*   **@param** `username` 要嵌入CSR中的用户名 (Common Name)。
*   **@param** `out_csr_pem` (输出) 指向 `char*` 的指针，函数将分配内存并存储PEM字符串。调用者需使用 `free_csr_pem()` 释放。
*   **返回:** `0` 成功, `-1` 失败。

---
`int verify_user_certificate(const char* user_cert_pem, const char* trusted_ca_cert_pem, const char* expected_username)`
*   **描述:** 执行完整的证书验证流程。
*   **@param** `user_cert_pem` 要验证的用户证书 (PEM格式)。
*   **@param** `trusted_ca_cert_pem` 受信任的根CA证书 (PEM格式)。
*   **@param** `expected_username` 期望从证书主体中匹配的用户名。
*   **返回:** `0` 验证成功, 负值表示不同类型的失败（详见头文件）。

---
*(其他 `pki_handler` 函数如 `free_csr_pem`, `extract_public_key_from_cert`，请参考头文件中的详细注释。)*

### `secure_memory` 模块
*头文件: `src/common/secure_memory.h`*

---
`void* secure_alloc(size_t size)`
*   **描述:** 分配一块受保护的、不可被交换到磁盘的内存。
*   **@param** `size` 要分配的字节数。
*   **返回:** 成功时返回指针，失败时返回 `NULL`。

---
`void secure_free(void* ptr)`
*   **描述:** 在释放前安全地擦除一块受保护的内存，然后释放它。
*   **@param** `ptr` 指向由 `secure_alloc` 分配的内存。

---

## 📜 证书说明

本项目使用 **X.509 v3** 证书标准。在演示程序 (`main.c`) 和测试代码中，我们通过 `generate_test_ca` 和 `sign_csr_with_ca` 两个辅助函数模拟了一个迷你的证书颁发机构（CA）。

*   **自签名根CA证书:** `generate_test_ca` 创建了一个自签名的根CA证书。在真实世界中，这个根证书会被预置在客户端中作为信任的锚点。为了使其成为一个合格的CA证书，我们为其添加了必要的 X.509 v3 扩展，如 `Basic Constraints (CA:TRUE)` 和 `Key Usage`。
*   **用户证书:** `sign_csr_with_ca` 模拟了CA服务器的操作，它接收用户的CSR，并使用CA的私钥对其进行签名，最终生成用户的证书。

在 `verify_user_certificate` 函数中，正是利用了 `trusted_ca_cert_pem` 参数提供的根CA证书，来验证用户证书的签名链是否可信。

## 🤝 贡献

欢迎对本项目进行改进！如果您发现了bug或有功能建议，请随时提交 Pull Request 或创建 Issue。

## 📄 许可证

本项目采用 [MIT License](LICENSE) 授权。