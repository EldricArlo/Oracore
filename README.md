# Oracipher Core High-Security Hybrid Encryption Kernel Library

| Build | License | Language | Dependencies |
| :---: | :---: | :---: | :--- |
| ![Build Status](https://img.shields.io/badge/build-passing-brightgreen) | ![License](https://img.shields.io/badge/license-Dual--Licensed-blue) | ![Language](https://img.shields.io/badge/language-C11-purple) | ![Libsodium](https://img.shields.io/badge/libsodium-v1.0.18+-brightgreen) ![OpenSSL](https://img.shields.io/badge/OpenSSL-v3.0+-0075A8) ![Libcurl](https://img.shields.io/badge/libcurl-v7.68+-E5522D) |

## 1. 😎 项目愿景与核心原则

本项目是一个使用 C11 标准实现的、专注于安全性的高级混合加密内核库。它旨在提供一个经过实战检验的蓝图，展示如何将行业领先的密码学库（**libsodium**, **OpenSSL**, **libcurl**）组合成一个健壮、可靠且易于使用的端到端加密解决方案。

我们的设计遵循以下核心安全原则：

*   🥸 **选择经审查的现代密码学：** 绝不自行实现加密算法。只使用社区公认的、抗侧信道攻击的现代密码学原语。
*   🤠 **纵深防御：** 安全性不依赖于任何单一层面。从内存管理、API设计到协议流程，层层设防。
*   🙃 **安全默认值与“故障关闭”：** 系统的默认行为必须是安全的。在遇到不确定状态（如无法验证证书吊销状态）时，系统必须选择失败并终止操作（Fail-Closed），而非继续执行。
*   🫥 **最小化敏感数据暴露：** 私钥等关键数据的生命周期、作用域和内存驻留时间必须被严格控制在绝对必要的最小范围内。

## 2. 🥲 核心特性

*   😮 **健壮的混合加密模型:**
    *   **对称加密:** 为大数据块提供基于 **XChaCha20-Poly1035** 的AEAD流式加密，为小数据块提供单次AEAD加密。
    *   **非对称加密:** 使用 **X25519** (基于 Curve25519) 对对称会话密钥进行密钥封装，确保只有预期的接收者才能解密。

*   🫨 **现代化的密码学原语栈:**
    *   **密钥派生:** 采用 **Argon2id**，这是当前密码哈希竞赛的获胜者，能有效抵御 GPU 和 ASIC 破解。
    *   **数字签名:** 采用 **Ed25519**，提供高速、高安全性的数字签名能力。
    *   **密钥统一:** 巧妙地利用 Ed25519 密钥可安全转换为 X25519 密钥的特性，使用一套主密钥对同时满足签名和加密的需求。

*   😏 **全面的公钥基础设施 (PKI) 支持:**
    *   **证书生命周期:** 支持生成符合 X.509 v3 标准的证书签名请求 (CSR)。
    *   **严格的证书验证:** 提供标准化的证书验证流程，包括信任链、有效期和主题匹配。
    *   **强制的吊销检查 (OCSP):** 内置严格的在线证书状态协议 (OCSP) 检查，并采用“故障关闭”策略，在无法确认证书状态良好时立即中止操作。

*   🧐 **固若金汤的内存安全:**
    *   通过公共 API 暴露 `libsodium` 的安全内存功能，允许客户端安全地处理敏感数据（如会话密钥）。
    *   所有内部私钥均存储在被锁定的内存中，**防止被操作系统交换到磁盘**，并在释放前被安全擦除。

*   😵‍💫 **高质量的工程实践:**
    *   **清晰的API边界:** 提供一个统一的公共头文件 `hsc_kernel.h`，采用不透明指针封装所有内部实现细节，实现了高内聚、低耦合。
    *   **经过单元测试:** 包含一套覆盖核心加密和PKI功能的单元测试，确保代码的正确性和可靠性。
    *   **完善的文档与示例:** 提供详尽的 `README.md` 以及可直接运行的演示程序和命令行工具。

## 3. 🤓 项目结构

项目采用清晰、分层的目录结构，以实现关注点分离。

```
.
├── include/
│   └── hsc_kernel.h      # [核心] 唯一的公共 API 头文件
├── src/                  # 源代码
│   ├── common/           # 通用内部模块 (安全内存, 安全规范)
│   ├── core_crypto/      # 核心加密内部模块 (libsodium 封装)
│   ├── pki/              # PKI 内部模块 (OpenSSL, libcurl 封装)
│   ├── hsc_kernel.c      # [核心] 公共 API 的实现
│   ├── main.c            # API 使用示例：端到端流程演示程序
│   └── cli.c             # API 使用示例：功能强大的命令行工具
├── tests/                # 单元测试
│   ├── test_*.c          # 各模块的单元测试
│   └── test_helpers.h/.c # 测试辅助函数
├── Makefile              # 构建与任务管理脚本
└── README.md             # 本项目的说明文档
```

## 4. 🤥 快速入门

### 4.1. 依赖环境

*   **构建工具:** `make`
*   **C 编译器:** `gcc` 或 `clang` (需支持 C11 标准)
*   **libsodium:** (`libsodium-dev`)
*   **OpenSSL:** 建议 **v3.0** 或更高版本 (`libssl-dev`)
*   **libcurl:** (`libcurl4-openssl-dev`)

**在 Debian/Ubuntu 上一键安装:**
```bash
sudo apt-get update
sudo apt-get install build-essential libsodium-dev libssl-dev libcurl4-openssl-dev
```

### 4.2. 编译与测试

1.  **编译所有目标 (库, 演示程序, CLI, 测试):**
    ```bash
    make all
    ```

2.  **运行单元测试 (关键步骤):**
    ```bash
    make run-tests
    ```
    > 😝 **关于 OCSP 测试的预期行为说明**
    >
    > `test_pki_verification` 的一个测试用例会故意使用一个指向无效 OCSP 服务器的证书进行验证。由于网络请求必然失败，`hsc_verify_user_certificate` 函数**必须**返回 `-4` 以表示吊销状态检查失败。测试代码会断言返回值确实是 `-4`，以此证明我们的“故障关闭”安全机制工作正常。

3.  **运行演示程序:**
    ```bash
    ./bin/hsc_demo
    ```

4.  **运行命令行工具:**
    ```bash
    ./bin/hsc_cli --help
    ```

5.  **清理构建文件:**
    ```bash
    make clean
    ```

## 5. ☺️ 使用指南

### 5.1. 作为命令行工具 (`hsc_cli`)

`hsc_cli` 是一个功能齐全、**支持灵活参数顺序**的命令行工具，用于执行所有核心的加密和 PKI 操作。

**完整工作流示例：Alice 加密文件并安全地发送给 Bob**

1.  **😒 (双方) 生成主密钥对:**
    ```bash
    ./bin/hsc_cli gen-keypair alice
    ./bin/hsc_cli gen-keypair bob
    ```

2.  **☺️ (双方) 生成 CSR 并获取证书:** (此处假设 CA 已签发 `alice.pem` 和 `bob.pem`)
    ```bash
    ./bin/hsc_cli gen-csr alice.key "alice@example.com"
    # (将 alice.csr 发送给 CA, 获得 alice.pem)
    ```

3.  **🤨 (Alice) 验证 Bob 的证书:** (假设 `ca.pem` 是受信任的根 CA 证书)
    ```bash
    ./bin/hsc_cli verify-cert bob.pem --ca ca.pem --user "bob@example.com"
    ```
    > **提示:** 带有值的选项 (如 `--ca` 和 `--user`) 现在可以按任意顺序列出。

4.  **😑 (Alice) 加密文件给 Bob:**
    ```bash
    echo "This is top secret information." > secret.txt
    ./bin/hsc_cli encrypt secret.txt --to bob.pem --from alice.key
    ```
    现在 Alice 可以将 `secret.hsc` 和她自己的证书 `alice.pem` 发送给 Bob。

5.  **😉 (Bob) 收到文件后解密:**
    ```bash
    # Bob 也可以调换 --from 和 --to 的顺序
    ./bin/hsc_cli decrypt secret.hsc --to bob.key --from alice.pem
    cat secret.decrypted
    ```

### 5.2. 作为库集成到您的项目中

`src/main.c` 是一个绝佳的集成示例。以下是典型的 API 调用流程：

1.  **全局初始化:** 在程序启动时，调用 `hsc_init()`。
    ```c
    #include "hsc_kernel.h"
    
    int main() {
        if (hsc_init() != 0) {
            // 处理致命错误
        }
        // ... 您的代码 ...
        hsc_cleanup();
        return 0;
    }
    ```

2.  **发送方 (Alice) 加密数据:**
    ```c
    // 1. 生成一次性的会话密钥
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    randombytes_buf(session_key, sizeof(session_key));

    // 2. 使用会话密钥通过 AEAD 加密数据 (适用于小数据)
    const char* message = "Secret message";
    size_t enc_buf_size = strlen(message) + HSC_AEAD_NONCE_BYTES + HSC_AEAD_TAG_BYTES;
    unsigned char* encrypted_data = malloc(enc_buf_size);
    unsigned long long encrypted_data_len;
    hsc_aead_encrypt(encrypted_data, &encrypted_data_len, 
                     (const unsigned char*)message, strlen(message), session_key);

    // 3. 验证接收方 (Bob) 的证书
    if (hsc_verify_user_certificate(bob_cert_pem, ca_pem, "bob@example.com") != 0) {
        // 证书无效，中止！
    }

    // 4. 从 Bob 的证书中提取其公钥
    unsigned char bob_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    hsc_extract_public_key_from_cert(bob_cert_pem, bob_pk);

    // 5. 使用 Bob 的公钥和 Alice 的私钥来封装会话密钥
    // (假设 alice_kp 是已加载的 hsc_master_key_pair*)
    unsigned char encapsulated_key[...]; size_t encapsulated_key_len;
    hsc_encapsulate_session_key(encapsulated_key, &encapsulated_key_len, 
                                session_key, sizeof(session_key),
                                bob_pk, alice_kp);
    
    // 6. 将 encrypted_data 和 encapsulated_key 一同发送给 Bob
    ```

3.  **接收方 (Bob) 解密数据:**
    ```c
    // 1. 从发送方 (Alice) 的证书中提取其公钥
    unsigned char alice_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    hsc_extract_public_key_from_cert(alice_cert_pem, alice_pk);
    
    // 2. 使用 Alice 的公钥和 Bob 自己的私钥来解封装会话密钥
    // (假设 bob_kp 是已加载的 hsc_master_key_pair*)
    unsigned char* dec_session_key = hsc_secure_alloc(HSC_SESSION_KEY_BYTES);
    if (hsc_decapsulate_session_key(dec_session_key, encapsulated_key, enc_key_len,
                                    alice_pk, bob_kp) != 0) {
        // 解封装失败！
    }

    // 3. 使用恢复的会话密钥解密数据
    unsigned char final_message[...]; unsigned long long final_len;
    if (hsc_aead_decrypt(final_message, &final_len,
                         encrypted_data, encrypted_data_len, dec_session_key) != 0) {
        // 解密失败！数据被篡改
    }

    // 4. 使用完毕后，安全地释放会话密钥
    hsc_secure_free(dec_session_key);
    ```

## 6. 😶 技术架构深度解析

本项目的核心是**混合加密（Hybrid Encryption）**模型，它结合了非对称加密和对称加密的优点，实现了既安全又高效的数据传输。

**数据流与密钥关系图:**

```
SENDER (ALICE)                                           RECIPIENT (BOB)
========================================================================
[ 原始数据 ] -> 生成 [会话密钥]
                    |        |
(对称加密) <---------'        '-> (非对称封装) 使用: Bob公钥, Alice私钥
     |                                |
[加密数据]                     [封装后的会话密钥]
     |                                |
     '----------------. .-------------'
                      | |
                      v v
                  [ 传输包 ]
                       |
   ==================> | 网络/文件传输 =================>
                       |
                  [ 传输包 ]
                      | |
           .----------' '-------------.
           |                          |
[封装后的会话密钥]                 [加密数据]
           |                          |
           v                          |
(非对称解封装) 使用: Bob私钥, Alice公钥 |
           |                          |
           v                          |
      [恢复的会话密钥] <---------------' (对称解密)
           |
           v
      [ 原始数据 ]
```

## 7. 😄 高级配置：通过环境变量增强安全性

为了在不修改代码的情况下适应未来更强的硬件和安全需求，本项目支持通过环境变量来**提升**密钥派生函数 (Argon2id) 的计算强度。

*   **`HSC_ARGON2_OPSLIMIT`**: 设置 Argon2id 的操作（计算）轮数。
*   **`HSC_ARGON2_MEMLIMIT`**: 设置 Argon2id 的内存使用量（以字节为单位）。

**重要安全说明：** 此功能**只能用于提升安全参数**。如果设置的环境变量值低于项目中内置的最小安全基线，程序将自动忽略这些不安全的值，并强制使用内置的最小值。

** 新增使用示例:**

```bash
# 示例：将操作限制提升至 10，内存限制提升至 512MB。
# 注意：HSC_ARGON2_MEMLIMIT 需要以字节为单位。
# 512 * 1024 * 1024 = 536870912 字节。
export HSC_ARGON2_OPSLIMIT=10
export HSC_ARGON2_MEMLIMIT=536870912

# 在设置了环境变量的 Shell 中运行程序，它将自动使用这些更强的参数。
./bin/hsc_cli gen-keypair my_strong_key
```

## 8. 😀 API 核心参考 (`include/hsc_kernel.h`)

### 初始化与清理
| 函数 | 描述 |
| :--- | :--- |
| `int hsc_init()` | **(必须首先调用)** 初始化整个库。 |
| `void hsc_cleanup()` | 在程序退出前调用，释放全局资源。 |

### 密钥管理
| 函数 | 描述 |
| :--- | :--- |
| `hsc_master_key_pair* hsc_generate_master_key_pair()` | 生成一个全新的主密钥对。 |
| `hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(...)` | 从文件加载私钥。 |
| `int hsc_save_master_key_pair(...)` | 将密钥对保存到文件。 |
| `void hsc_free_master_key_pair(hsc_master_key_pair** kp)` | 安全地释放主密钥对。 |

### PKI 与证书
| 函数 | 描述 |
| :--- | :--- |
| `int hsc_generate_csr(...)` | 生成 PEM 格式的证书签名请求 (CSR)。 |
| `int hsc_verify_user_certificate(...)` | **(核心)** 执行完整的证书验证 (签名链, 有效期, 主题, OCSP)。 |
| `int hsc_extract_public_key_from_cert(...)` | 从已验证的证书中提取公钥。 |

### 密钥封装 (非对称)
| 函数 | 描述 |
| :--- | :--- |
| `int hsc_encapsulate_session_key(...)` | 使用接收者公钥加密一个会话密钥。 |
| `int hsc_decapsulate_session_key(...)` | 使用接收者私钥解密一个会话密钥。 |

### 数据加密 (对称)
| 函数 | 描述 |
| :--- | :--- |
| `int hsc_aead_encrypt(...)` | 使用 AEAD 对**小数据块**进行认证加密。 |
| `int hsc_aead_decrypt(...)` | 解密并验证由 `hsc_aead_encrypt` 加密的数据。 |

### 流式加密 (对称，适用于大文件)
| 函数 | 描述 |
| :--- | :--- |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(...)` | 创建一个加密流状态对象。 |
| `hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(...)` | 创建一个解密流状态对象。 |
| `int hsc_crypto_stream_push(...)` | 加密流的一个数据块。 |
| `int hsc_crypto_stream_pull(...)` | 解密流的一个数据块。 |
| `void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state)` | 释放流状态对象。 |

### 安全内存
| 函数 | 描述 |
| :--- | :--- |
| `void* hsc_secure_alloc(size_t size)` | 分配一块受保护的、不可交换的内存。 |
| `void hsc_secure_free(void* ptr)` | 安全地擦除并释放受保护的内存。 |


## 9. 🥳 贡献

我们欢迎任何形式的贡献！如果您发现了 bug、有功能建议或想改进文档，请随时提交 Pull Request 或创建 Issue。

## 10. 🥺 证书说明 (Certificate Description)

本项目采用 **X.509 v3** 证书体系来将一个公钥与一个用户身份（如 `alice@example.com`）绑定起来，从而建立信任。证书验证流程包括**签名链验证**、**有效期检查**、**主题身份核对**和**吊销状态检查 (OCSP)**，并采用严格的“故障关闭”策略。

## 11. 🥸 许可证 (License) - 双重许可模式

本项目采用**双重许可 (Dual-License)** 模式：

### 1. GNU Affero General Public License v3.0 (AGPLv3)
适用于开源项目、学术研究、个人学习。要求任何修改或通过网络提供服务的衍生作品也必须以AGPLv3开放其完整源代码。

### 2. 商业许可 (Commercial License)
适用于任何闭源的商业应用程序、产品或服务。如果您不希望受到AGPLv3开源条款的约束，您必须获得一份商业许可。

**如需获取商业许可，请联系: `eldric520lol@gmail.com`**


