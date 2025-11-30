<div align="center">
  <img src="./src/media/icon-256.png" alt="Oracipher Icon" width="128">
  <h1 style="border-bottom: none;">Oracipher Core</h1>

# High-Security Hybrid Encryption Kernel Library

| Build & Test | License | Language | Dependencies |
| :---: | :---: | :---: | :---: |
| ![Build Status](https://img.shields.io/badge/tests-passing-brightgreen) | ![License](https://img.shields.io/badge/license-Dual--Licensed-blue) | ![Language](https://img.shields.io/badge/language-C11-purple) | ![Libsodium](https://img.shields.io/badge/libsodium-v1.0.18+-brightgreen) ![OpenSSL](https://img.shields.io/badge/OpenSSL-v3.0+-0075A8) ![Libcurl](https://img.shields.io/badge/libcurl-v7.68+-E5522D) |

</div>

---

### **目录**
1.  [项目愿景与核心原则](#1-项目愿景与核心原则)
2.  [核心特性](#2-核心特性)
3.  [项目结构](#3-项目结构)
4.  [快速开始](#4-快速开始)
    *   [4.1 依赖环境](#41-依赖环境)
    *   [4.2 编译与测试](#42-编译与测试)
5.  [使用指南](#5-使用指南)
    *   [5.1 作为命令行工具使用](#51-作为命令行工具使用hsc_cli--test_ca_util)
    *   [5.2 作为库在您的项目中使用](#52-作为库在您的项目中使用)
6.  [深度剖析：技术架构](#6-深度剖析技术架构)
7.  [高级配置：通过环境变量增强安全性](#7-高级配置通过环境变量增强安全性)
8.  [高级主题：加密模式对比](#8-高级主题加密模式对比)
9.  [核心API参考](#9-核心api参考includehsc_kernelh)
10. [贡献](#10-贡献)
11. [证书说明](#11-证书说明)
12. [许可证](#12-许可证---双重许可模式)

---

## 1. 项目愿景与核心原则

本项目是一个以安全为核心、采用C11标准实现的高级混合加密内核库。它旨在提供一个经过实战检验的蓝图，展示如何将行业领先的密码学库（**libsodium**, **OpenSSL**, **libcurl**）组合成一个健壮、可靠且易于使用的端到端加密解决方案。

我们的设计遵循以下核心安全原则：

*   **选择经过审查的现代密码学：** 绝不自研加密算法。只使用被社区广泛认可的、能抵抗侧信道攻击的现代密码学原语。
*   **深度防御：** 安全性不依赖于任何单一层面。我们在内存管理、API设计、协议流程等多个层面实施保护。
*   **安全默认与“故障关闭”策略：** 系统的默认行为必须是安全的。当面临不确定状态（例如，无法验证证书吊销状态）时，系统必须选择失败并终止操作（故障关闭），而不是继续运行。
*   **最小化敏感数据暴露：** 严格控制私钥等关键数据在内存中的生命周期、作用域和驻留时间，使其达到绝对必要的最小值。

## 2. 核心特性

*   **健壮的混合加密模型：**
    *   **对称加密：** 基于 **XChaCha20-Poly1305** 提供AEAD流式加密（适用于大数据块）和一次性AEAD加密（适用于小数据块）。
    *   **非对称加密：** 使用 **X25519**（基于Curve2519）对对称会话密钥进行密钥封装，确保只有预期的接收者可以解密。

*   **现代密码学原语栈：**
    *   **密钥派生：** 采用密码哈希竞赛的获胜者 **Argon2id**，有效抵抗GPU和ASIC的破解尝试。
    *   **数字签名：** 利用 **Ed25519** 提供高速、高安全性的数字签名能力。
    *   **密钥统一：** 巧妙地利用了Ed25519密钥可以安全转换为X25519密钥的特性，允许单一主密钥对同时满足签名和加密的需求。

*   **完善的公钥基础设施 (PKI) 支持：**
    *   **证书生命周期：** 支持生成符合X.509 v3标准的证书签名请求 (CSR)。
    *   **严格的证书验证：** 提供标准化的证书验证流程，包括信任链、有效期和主体匹配。
    *   **强制吊销检查 (OCSP)：** 内置严格的在线证书状态协议 (OCSP) 检查，并采用“故障关闭”策略，如果无法确认证书的良好状态，操作将立即中止。

*   **坚如磐石的内存安全：**
    *   通过公共API暴露`libsodium`的安全内存函数，允许客户端安全地处理敏感数据（如会话密钥）。
    *   **[安全文档记录]** 所有内部私钥**及其他关键秘密（如密钥种子、中间哈希值）**均存储在锁定内存中，**防止被操作系统交换到磁盘**，并在释放前被安全擦除。与第三方库（如OpenSSL）的数据边界被精心管理。当敏感数据必须跨越到标准内存区域时（例如在 `generate_csr` 中传递种子给OpenSSL），本库采用深度防御技术（如在使用后立即清理内存缓冲区）来缓解固有风险，这代表了在与非安全内存感知的库交互时的最佳实践。

*   **高质量的工程实践：**
    *   **清晰的API边界：** 提供单一的公共头文件 `hsc_kernel.h`，通过不透明指针封装所有内部实现细节，实现高内聚、低耦合。
    *   **全面的测试套件：** 包含一套单元和集成测试，覆盖核心密码学、PKI和高级API功能，确保代码的正确性和可靠性。
    *   **解耦的日志系统：** 实现基于回调的日志机制，让客户端应用程序完全控制日志消息的显示方式和位置，使库适用于任何环境。
    *   **详尽的文档与示例：** 提供详细的 `README.md`，以及一个可直接运行的演示程序和一个功能强大的命令行工具。

## 3. 项目结构

项目采用清晰、分层的目录结构来实现关注点分离。

```.
├── include/
│   └── hsc_kernel.h      # [核心] 唯一的公共API头文件
├── src/                  # 源代码
│   ├── common/           # 通用内部模块 (安全内存, 日志)
│   ├── core_crypto/      # 核心加密内部模块 (libsodium 包装)
│   ├── pki/              # PKI 内部模块 (OpenSSL, libcurl 包装)
│   ├── hsc_kernel.c      # [核心] 公共API的实现
│   ├── main.c            # API用法示例: 端到端演示程序
│   └── cli.c             # API用法示例: 功能强大的命令行工具
├── tests/                # 单元测试和测试工具
│   ├── test_*.c          # 各模块的单元测试
│   ├── test_api_integration.c # [新增] 高级API的端到端测试
│   ├── test_helpers.h/.c # 测试辅助函数 (CA生成, 签名)
│   └── test_ca_util.c    # 独立的测试CA工具的源代码
├── Makefile              # 构建和任务管理脚本
└── README.md             # 本项目的文档
```

## 4. 快速开始

### 4.1 依赖环境

*   **构建工具:** `make`
*   **C 编译器:** `gcc` 或 `clang` (支持C11和 `-Werror`)
*   **libsodium:** (`libsodium-dev`)
*   **OpenSSL:** 推荐 **v3.0** 或更高版本 (`libssl-dev`)
*   **libcurl:** (`libcurl4-openssl-dev`)

**在主流系统上的安装:**

*   **Debian/Ubuntu:**
    ```bash
    sudo apt-get update
    sudo apt-get install build-essential libsodium-dev libssl-dev libcurl4-openssl-dev
    ```
*   **Fedora/RHEL/CentOS:**
    ```bash
    sudo dnf install gcc make libsodium-devel openssl-devel libcurl-devel
    ```
*   **macOS (使用 Homebrew):**
    ```bash
    brew install libsodium openssl@3 curl
    ```

### 4.2 编译与测试

项目被设计为高度可移植，并避免了平台特定的硬编码路径，确保它能在所有支持的系统上正确构建和运行。

1.  **编译所有目标 (库, 演示程序, 命令行工具, 测试):**
    ```bash
    make all
    ```

2.  **运行全面的测试套件 (关键步骤):**
    ```bash
    make run-tests
    ```
    > **关于OCSP测试预期行为的重要说明**
    >
    > `test_pki_verification` 中的一个测试用例会故意验证一个指向不存在的本地OCSP服务器（`http://127.0.0.1:8888`）的证书。网络请求将会失败，此时 `hsc_verify_user_certificate` 函数**必须**返回 `-12` (即 `HSC_ERROR_CERT_REVOKED_OR_OCSP_FAILED` 的错误码)。测试程序会断言这个特定的返回值。
    >
    > 这个“失败”是**预期的、正确的行为**，因为它完美地证明了我们的“故障关闭”安全策略得到了正确实施：**如果因任何原因无法确认证书的吊销状态，该证书将被视为无效。**

3.  **运行演示程序:**
    ```bash
    ./bin/hsc_demo
    ```

4.  **探索命令行工具:**
    ```bash
    ./bin/hsc_cli
    ```

5.  **清理构建文件:**
    ```bash
    make clean
    ```

## 5. 使用指南

### 5.1 作为命令行工具使用 (`hsc_cli` & `test_ca_util`)

本节提供了一个完整的、自包含的工作流，演示了两位用户（Alice和Bob）如何使用提供的命令行工具进行安全的文件交换。

**工具角色:**
*   `./bin/test_ca_util`: 一个辅助工具，用于模拟一个证书颁发机构(CA)，负责生成根证书和签署用户证书。
*   `./bin/hsc_cli`: 核心的客户端工具，用于密钥生成、CSR创建、证书验证以及文件的加解密。

**完整工作流示例: Alice 加密一个文件并安全地发送给 Bob**

1.  **(设置) 创建一个测试证书颁发机构 (CA):**
    *我们使用 `test_ca_util` 来生成一个根CA密钥和一个自签名证书。*
    ```bash
    ./bin/test_ca_util gen-ca ca.key ca.pem
    ```

2.  **(Alice & Bob) 生成各自的主密钥对:**
    ```bash
    ./bin/hsc_cli gen-keypair alice
    ./bin/hsc_cli gen-keypair bob
    ```
    *这将创建 `alice.key`, `alice.pub`, `bob.key`, 和 `bob.pub`。*

3.  **(Alice & Bob) 生成证书签名请求 (CSRs):**
    ```bash
    ./bin/hsc_cli gen-csr alice.key "alice@example.com"
    ./bin/hsc_cli gen-csr bob.key "bob@example.com"
    ```
    *这将创建 `alice.csr` 和 `bob.csr`。*

4.  **(CA) 签署 CSR 以颁发证书:**
    *CA 使用其私钥 (`ca.key`) 和证书 (`ca.pem`) 来签署CSR。*
    ```bash
    ./bin/test_ca_util sign alice.csr ca.key ca.pem alice.pem
    ./bin/test_ca_util sign bob.csr ca.key ca.pem bob.pem
    ```
    *现在 Alice 和 Bob 拥有了他们正式的证书, `alice.pem` 和 `bob.pem`。*

5.  **(Alice) 在发送前验证 Bob 的证书:**
    *Alice 使用受信任的CA证书 (`ca.pem`) 来验证Bob的身份。这是信任其证书之前的关键一步。*
    ```bash
    ./bin/hsc_cli verify-cert bob.pem --ca ca.pem --user "bob@example.com"
    ```

6.  **(Alice) 为 Bob 加密一个文件:**
    *Alice 现在有多种选择:*

    **选项 A: 基于证书并进行验证 (安全默认 & 推荐)**
    > 这是标准的、安全的操作方式。工具**要求**Alice提供CA证书和预期的用户名，以便在加密前对Bob的证书执行完整、严格的验证。
    ```bash
    echo "This is top secret information." > secret.txt
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --ca ca.pem --user "bob@example.com"
    ```

    **选项 B: 基于证书但不验证 (危险 - 仅限专家)**
    > 如果Alice绝对确定证书的真实性并希望跳过验证，她必须明确使用 `--no-verify` 标志。**不推荐这样做。**
    ```bash
    # 请极度谨慎使用!
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key --no-verify
    ```

    **选项 C: 直接密钥模式 (高级 - 用于预信任的密钥)**
    *如果Alice已经通过一个安全的、可信的渠道获得了Bob的公钥 (`bob.pub`)，她可以直接对其加密，绕过所有证书逻辑。*
    ```bash
    ./bin/hsc_cli encrypt secret.txt --recipient-pk-file bob.pub --from alice.key
    ```
    *所有选项都会创建 `secret.txt.hsc`。Alice现在可以将 `secret.txt.hsc` 和她的证书 `alice.pem` 发送给 Bob。*

7.  **(Bob) 收到后解密文件:**
    *Bob 使用他的私钥 (`bob.key`) 来解密文件。根据Alice的加密方式，他将需要Alice的证书 (`alice.pem`) 或她的原始公钥 (`alice.pub`)。*

    **如果 Alice 使用了选项 A 或 B (证书):**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --from alice.pem
    ```

    **如果 Alice 使用了选项 C (直接密钥):**
    ```bash
    ./bin/hsc_cli decrypt secret.txt.hsc --to bob.key --sender-pk-file alice.pub
    ```
    *两个命令都会生成 `secret.txt.decrypted`。*
    ```bash
    cat secret.txt.decrypted
    ```

### 5.2 作为库在您的项目中使用

`src/main.c` 是一个优秀的集成示例。典型的API调用流程如下：

1.  **全局初始化与日志设置:** 在启动时调用 `hsc_init()` 并注册一个日志回调。
    ```c
    #include "hsc_kernel.h"
    #include <stdio.h>

    // 为您的应用程序定义一个简单的日志函数
    void my_app_logger(int level, const char* message) {
        // 示例: 将错误打印到 stderr，信息打印到 stdout
        if (level >= 2) { // 2 = ERROR
            fprintf(stderr, "[HSC_LIB_ERROR] %s\n", message);
        } else {
            printf("[HSC_LIB_INFO] %s\n", message);
        }
    }

    int main() {
        if (hsc_init() != HSC_OK) {
            // 处理致命错误
        }
        // 向库注册您的日志函数
        hsc_set_log_callback(my_app_logger);

        // ... 您的代码 ...
        hsc_cleanup();
        return 0;
    }
    ```

2.  **发送方 (Alice) 加密数据:**
    ```c
    // 1. 生成一个一次性的会话密钥
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    hsc_random_bytes(session_key, sizeof(session_key));

    // 2. 使用AEAD以会话密钥加密数据 (适用于小数据)
    const char* message = "Secret message";
    // ... (加密逻辑同示例) ...

    // 3. 验证接收者 (Bob) 的证书
    if (hsc_verify_user_certificate(bob_cert_pem, ca_pem, "bob@example.com") != HSC_OK) {
        // 证书无效，中止！库将通过您的回调记录详细信息。
    }

    // 4. 从他的证书中提取 Bob 的公钥
    unsigned char bob_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert(bob_cert_pem, bob_pk) != HSC_OK) {
        // 处理提取错误
    }

    // 5. 封装会话密钥
    // ... (封装逻辑同示例) ...
    ```

3.  **接收方 (Bob) 解密数据:**
    *解密逻辑保持不变，但任何在解封装或AEAD解密期间的内部错误现在都将通过您注册的 `my_app_logger` 回调报告，而不是直接污染 `stderr`。*

## 6. 深度剖析：技术架构

本项目的核心是混合加密模型，它结合了非对称和对称密码学的优点，以实现既安全又高效的数据传输。

**数据流与密钥关系图:**

```
发送方 (ALICE)                                           接收方 (BOB)
========================================================================
[ 明文 ] ------> 生成 [ 会话密钥 ]
                |          |
(对称加密) <-----'          '-> (非对称封装) 使用: Bob的公钥, Alice的私钥
     |                                       |
[ 加密数据 ]                         [ 封装后的会话密钥 ]
     |                                       |
     '--------------------.  .---------------'
                          |  |
                          v  v
                     [ 数据包 ]
                          |
   ==================>  通过网络/文件  =================>
                          |
                     [ 数据包 ]
                          |  |
           .--------------'  '----------------.
           |                                  |
[ 封装后的会话密钥 ]                 [ 加密数据 ]
           |                                  |
           v                                  |
(非对称解封装) 使用: Bob的私钥, Alice的公钥
           |                                  |
           v                                  |
      [ 恢复的会话密钥 ] <--------$----' (对称解密)
           |
           v
      [ 明文 ]
```

## 7. 高级配置：通过环境变量增强安全性

为了适应未来的硬件和安全需求而无需修改代码，本项目支持通过环境变量**增加**密钥派生函数 (Argon2id) 的计算成本。

*   **`HSC_ARGON2_OPSLIMIT`**: 设置Argon2id的操作次数（计算轮数）。
*   **`HSC_ARGON2_MEMLIMIT`**: 以字节为单位设置Argon2id的内存使用量。

**重要安全说明:** 此功能**只能用于增强安全参数**。如果环境变量中设置的值低于项目中内置的最低安全基线，程序将自动忽略这些不安全的值，并强制执行内置的最小值。

**用法示例:**

```bash
# 示例: 将操作限制增加到10，内存限制增加到512MB。
# 注意: HSC_ARGON2_MEMLIMIT 需要以字节为单位的值。
# 512 * 1024 * 1024 = 536870912 字节。
export HSC_ARGON2_OPSLIMIT=10
export HSC_ARGON2_MEMLIMIT=536870912

# 在设置了这些变量的shell中运行任何程序，都将自动使用这些更强的参数。
./bin/hsc_cli gen-keypair my_strong_key
```

## 8. 高级主题：加密模式对比

Oracipher Core 提供了两种截然不同的混合加密工作流，每种都有不同的安全保证。选择正确的模式至关重要。

### 基于证书的工作流 (默认 & 推荐)

*   **工作原理:** 使用X.509证书将用户身份（例如，`bob@example.com`）与其公钥绑定。
*   **安全保证:**
    *   **身份验证:** 以密码学方式验证公钥确实属于预期的接收者。
    *   **完整性:** 确保证书未被篡改。
    *   **吊销检查:** 通过OCSP主动检查证书是否已被证书颁发机构吊销。
*   **使用时机:** 在发送方和接收方没有预先存在的高度安全渠道来交换公钥的任何场景。这是大多数基于互联网的通信的标准。

### 直接密钥 (原始) 工作流 (高级)

*   **工作原理:** 绕过所有PKI和证书逻辑，直接对一个原始公钥文件进行加密。
*   **安全保证:**
    *   为加密数据本身提供了与证书模式相同级别的**机密性**和**完整性**。
*   **安全权衡:**
    *   **无身份验证:** 此模式**不会**验证密钥所有者的身份。用户全权负责确保他们正在使用的公钥的真实性。使用不正确或恶意的公钥将导致数据为错误的一方加密。
*   **使用时机:** 仅在封闭系统或特定协议中使用，其中公钥已通过独立的、可信的带外机制（例如，密钥固化在安全设备的固件中，或亲自验证）交换和验证。

## 9. 核心API参考 (`include/hsc_kernel.h`)

### 初始化与清理
| 函数 | 描述 |
| :--- | :--- |
| `int hsc_init()` | **(必须首先调用)** 初始化整个库。 |
| `void hsc_cleanup()` | 在程序退出前调用以释放全局资源。 |

### 密钥管理
| 函数 | 描述 |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | 生成一个新的主密钥对。 |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(...)` | 从文件加载一个私钥。 |
| `int hsc_save_master_key_pair(...)` | 将一个密钥对保存到文件。 |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | 安全地释放一个主密钥对。 |
| `int hsc_get_master_public_key(const hsc_master_key_pair* kp, ...)` | **[新增]** 从密钥对句柄中提取原始公钥。 |

### PKI & 证书
| 函数 | 描述 |
| :--- | :--- |
| `int hsc_generate_csr(...)` | 生成PEM格式的证书签名请求 (CSR)。 |
| `int hsc_verify_user_certificate(...)` | **(核心)** 执行完整的证书验证 (信任链, 有效期, 主体, OCSP)。 |
| `int hsc_extract_public_key_from_cert(...)` | 从一个已验证的证书中提取公钥。 |

### 密钥封装 (非对称)
| 函数 | 描述 |
| :--- | :--- |
| `int hsc_encapsulate_session_key(...)` | 使用接收者的公钥加密一个会话密钥。 |
| `int hsc_decapsulate_session_key(...)` | 使用接收者的私钥解密一个会话密钥。 |

### 流式加密 (对称, 适用于大文件)
| 函数 | 描述 |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | 创建一个加密流状态对象。 |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | 创建一个解密流状态对象。 |
| `int hsc_crypto_stream_push(...)` | 在流中加密一块数据。 |
| `int hsc_crypto_stream_pull(...)` | 在流中解密一块数据。 |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | 释放流状态对象。 |
| `int hsc_hybrid_encrypt_stream_raw(...)` | 使用原始公钥对文件执行完整的混合加密。 |
| `int hsc_hybrid_decrypt_stream_raw(...)` | 使用原始公钥对文件执行完整的混合解密。 |

### 数据加密 (对称, 适用于小数据)
| 函数 | 描述 |
| :--- | :--- |
| `int hsc_aead_encrypt(...)` | 使用AEAD对**一小块数据**执行认证加密。 |
| `int hsc_aead_decrypt(...)` | 解密并验证由 `hsc_aead_encrypt` 加密的数据。 |

### 安全内存
| 函数 | 描述 |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | 分配一块受保护的、不可交换的内存。 |
| `void hsc_secure_free(void* ptr)` | 安全地擦除并释放一块受保护的内存。 |

### 日志
| 函数 | 描述 |
| :--- | :--- |
| `void hsc_set_log_callback(hsc_log_callback callback)` | **[新增]** 注册一个回调函数来处理所有内部的库日志。 |

## 10. 贡献

我们欢迎所有形式的贡献！如果您发现错误、有功能建议或希望改进文档，请随时提交 Pull Request 或创建 Issue。

## 11. 证书说明

本项目使用 **X.509 v3** 证书体系将公钥与用户身份（例如 `alice@example.com`）绑定，从而建立信任。证书验证过程包括**签名链验证**、**有效期检查**、**主体身份验证**和**吊销状态检查 (OCSP)**，所有这些都在严格的“故障关闭”策略下进行。

## 12. 许可证 - 双重许可模式

本项目在**双重许可**模型下分发：

### 1. GNU Affero General Public License v3.0 (AGPLv3)
适用于开源项目、学术研究和个人学习。它要求任何修改过的或通过网络提供服务的衍生作品也必须在AGPLv3下开放其完整源代码。

### 2. 商业许可
任何闭源的商业应用程序、产品或服务都必须获得。如果您不希望受到AGPLv3开源条款的约束，则必须获取商业许可。

**要获取商业许可，请联系: `eldric520lol@gmail.com`**
