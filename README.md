# Oracore: 一个 Python 密码库核心

[![PyPI Version](https://img.shields.io/pypi/v/oracore.svg)](https://pypi.org/project/oracore/)
[![Python Tests](https://github.com/EldricArlo/Oracore/actions/workflows/python-package.yml/badge.svg)](https://github.com/EldricArlo/Oracore/actions/workflows/python-package.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Oracore** 是一个为构建高性能、高安全性的本地密码管理器而设计的独立 Python 核心库。它将复杂的密码学操作、安全的数据库管理和灵活的数据格式处理封装在一个简洁、健壮且开发者友好的 API 之后。

---

## 目录

- [Oracore: 一个强大、安全且现代的 Python 密码库核心](#oracore-一个强大安全且现代的-python-密码库核心)
  - [目录](#目录)
  - [😎 为什么选择 Oracore？](#-为什么选择-oracore)
  - [😊 安装](#-安装)
  - [😎 快速上手：保险库 (Vault) 的生命周期](#-快速上手保险库-vault-的生命周期)
  - [🧐 API 详解](#-api-详解)
    - [`Vault` 核心 API](#vault-核心-api)
      - [初始化](#初始化)
      - [状态属性](#状态属性)
      - [生命周期方法](#生命周期方法)
      - [数据操作 (CRUD)](#数据操作-crud)
      - [安全数据传输](#安全数据传输)
      - [高级与危险操作](#高级与危险操作)
    - [`oracore.data_formats` 模块](#oracoredata_formats-模块)
  - [🤓 架构与代码逻辑](#-架构与代码逻辑)
  - [😉 文件结构](#-文件结构)
  - [🤨 安全最佳实践 (使用者责任)](#-安全最佳实践-使用者责任)
  - [🤗 测试与贡献](#-测试与贡献)
  - [😊 许可证](#-许可证)

---

## 😎 为什么选择 Oracore？

| 特性 | 描述 |
| :--- | :--- |
| 🛡️ **极致安全** | **安全是我们设计的基石，而非事后补充。** 我们采用行业黄金标准 **Argon2id** 进行密钥派生，使用 **Fernet (AES + HMAC)** 进行认证加密，并通过**常量时间比较**等最佳实践，从源头上杜绝时序攻击等常见漏洞。 |
| 🏛️ **现代架构** | **简洁的 API，强大的内核。** 通过优雅的**外观模式 (Facade)**，您只需与一个 `Vault` 对象交互。底层的高度模块化、**策略模式**驱动的导入器和**事务性数据库**操作，确保了代码的健壮性、可维护性和数据一致性。 |
| ⚡ **性能卓越** | **轻松应对海量数据。** Oracore 提供了基于**生成器**的高效 API (`get_all_entries_iter`)，即使面对包含数万条记录的密码库，也能保持极低的内存占用和流畅的性能。 |
| ✍️ **开发者友好** | **专注于您的应用逻辑，而非底层复杂性。** 完整的 **Python 类型提示**、精确的**自定义异常体系**以及灵活的**数据导入/导出**工具，为您提供了清晰、可预测且愉悦的开发体验。 |

---

## 😊 安装

在您的项目虚拟环境中通过 `pip` 安装 Oracore：

```bash
pip install oracore
```

---

## 😎 快速上手：保险库 (Vault) 的生命周期

与 Oracore 的所有交互都通过 `Vault` 对象进行。正确使用它需要遵循一个简单而严格的生命周期：**设置 (Setup) → 解锁 (Unlock) → 使用 (Use) → 锁定 (Lock)**。

以下是一个完整且健壮的典型用法示例：

```python
import os
from oracore import Vault, OracipherError, IncorrectPasswordError

# 1. 定义保险库文件的存储位置
data_directory = "./my_secure_vault"
vault = Vault(data_directory)
master_password = "my-super-secret-password-!@#" # 应从用户界面安全地获取

try:
    # 2. [设置] 检查保险库是否首次使用
    if not vault.is_setup:
        print("Vault not found. Setting it up now...")
        # 默认要求密码长度 >= 12，以增强安全性
        vault.setup(master_password)
        print("Vault setup complete.")

    # 3. [解锁] 对保险库进行任何操作前都必须解锁
    vault.unlock(master_password)
    print("Vault unlocked successfully!")

    # --- 4. [使用] 在解锁后执行所有操作 ---
    
    # a. 保存一个新的登录条目
    entry_data = {
        "name": "GitHub",
        "category": "Development",
        "details": {
            "username": "my_username",
            "password": "a_very_strong_password_generated",
            "url": "github.com",
            "notes": "Work account"
        }
    }
    new_entry_id = vault.save_entry(entry_data)
    print(f"Saved new entry with ID: {new_entry_id}")

    # b. 高效地遍历所有条目 (推荐方式)
    print("\nEntries in vault:")
    for entry in vault.get_all_entries_iter():
        print(f"- ID: {entry['id']}, Name: {entry['name']}")

except IncorrectPasswordError:
    print("Error: The master password was incorrect.")
except ValueError as e:
    # 捕获密码过短等验证错误
    print(f"Validation error: {e}")
except OracipherError as e:
    # 捕获所有其他 Oracore 特定错误
    print(f"A vault-related error occurred: {e}")
except Exception as e:
    print(f"An unexpected system error occurred: {e}")
finally:
    # 5. [锁定] [至关重要] 无论发生什么，都要确保在操作结束后锁定保险库
    if vault.is_unlocked:
        vault.lock()
        print("\nVault has been securely locked.")
```

---

## 🧐 API 详解

### `Vault` 核心 API

这是与 Oracore 交互的主要入口。

#### 初始化

-   `Vault(data_dir: str)`
    创建一个指向特定数据目录的 Vault 实例。如果目录不存在，会自动创建。

#### 状态属性

-   `vault.is_setup` -> `bool`
    检查保险库是否已被初始化（即已设置主密码）。

-   `vault.is_unlocked` -> `bool`
    检查保险库当前是否已解锁（即加密密钥已加载到内存中）。

#### 生命周期方法

-   `vault.setup(master_password: str, min_length: int = 12)`
    首次创建保险库。默认情况下，会强制要求主密码长度至少为12个字符，以鼓励安全实践。将 `min_length` 设置为 `0` 可以禁用此检查。

-   `vault.unlock(master_password: str)`
    使用主密码解锁保险库。成功后，可以执行所有数据操作。

-   `vault.lock()`
    锁定保险库，从内存中安全地清除加密密钥并关闭数据库连接。

#### 数据操作 (CRUD)

> **注意:** 以下所有方法都要求保险库处于**已解锁**状态，否则将抛出 `VaultLockedError`。

-   `vault.save_entry(entry_data: dict) -> int`
    保存或更新一个条目。如果 `entry_data` 字典中包含 `id` 键，则为更新操作；否则为创建操作。返回该条目的 `id`。

-   `vault.get_all_entries() -> list[dict]`
    获取所有条目并一次性加载到一个列表中。适用于条目数量较少的情况。

-   `vault.get_all_entries_iter() -> Iterator[dict]`
    **(推荐)** 以内存高效的迭代器（生成器）方式获取所有条目。这是处理大型密码库的最佳方式。

-   `vault.delete_entry(entry_id: int)`
    根据 ID 删除一个条目。

#### 安全数据传输

这是在不同设备间迁移或备份保险库的**推荐方式**。

-   `vault.export_to_skey(export_path: str)`
    安全地将整个保险库的所有条目导出到一个加密的 `.skey` 文件中。

    ```python
    # (假设 vault 已解锁)
    try:
        vault.export_to_skey("my_backup.skey")
        print("👍 Secure backup created.")
    except OracipherError as e:
        print(f"👎 Export failed: {e}")
    ```

-   `vault.import_from_skey(skey_path: str, backup_password: str)`
    将一个加密的 `.skey` 备份文件解密，并将其中的条目导入到**当前**保险库实例中。

    ```python
    # (假设 my_new_vault 已解锁)
    try:
        # backup_password 是创建该备份文件时所用的主密码
        my_new_vault.import_from_skey(
            skey_path="my_backup.skey",
            backup_password="password-of-the-original-vault"
        )
        print("👍 Successfully imported entries from backup.")
    except InvalidFileFormatError as e:
        print(f"👎 Import failed: Incorrect password or corrupt file.")
    ```

#### 高级与危险操作

-   `vault.change_master_password(old_password: str, new_password: str, min_length: int = 12)`
    更改主密码。此操作会用新密码派生的密钥重新加密整个数据库，确保安全。同样，默认会检查新密码的最小长度。

-   `vault.destroy_vault()`
    **(警告：不可逆)** 永久性地、安全地销毁整个保险库，包括其目录和所有文件。
    > **安全提示:** 此方法会尝试用随机数据覆写文件，但由于现代文件系统和SSD的复杂性，无法保证数据在法证级别上完全不可恢复。为获得最高安全性，请结合全盘加密使用。

---

### `oracore.data_formats` 模块

此模块提供处理**非加密**或**外部**数据格式的工具函数。

-   `data_formats.export_to_csv(entries: list) -> str`
    将条目列表导出为 CSV 格式的字符串。

-   `data_formats.import_from_file(file_path: str, file_content_bytes: bytes, password: str | None = None) -> list`
    一个高级的导入分发器，可以自动检测并解析多种外部文件格式（如 Google Chrome CSV, Samsung Pass .spass 等）。对于加密的外部格式（如 `.spass`），需要提供相应的密码。

---

## 🤓 架构与代码逻辑

Oracore 采用分层和模块化的架构设计，以实现高度的内聚和松散的耦合。

```
  [您的应用程序]
       │
       v
┌────────────────────┐
│  Vault (外观模式)  │  <--—— 唯一的公共交互入口
└────────────────────┘
       │              ┌──────────────────┐
       ├─ (协调) ——-> │  CryptoHandler   │ (负责所有密码学操作)
       │              └──────────────────┘
       │            
       │              ┌──────────────────┐
       ├─ (协调) ——-> │   DataManager    │ (负责数据库交互)
       │              └──────────────────┘
       │            
       │              ┌──────────────────┐
       └─ (委托) ——-> │  Data Formats    │ (负责导入/导出)
                      └──────────────────┘
                           │              ┌────────────────────┐
                           └─ (使用) ——-> │ Importers(策略模式) │
                                          └────────────────────┘
                                       

```

-   **`Vault` (外观层):** 实现了**外观模式 (Facade)**，作为客户端代码与库交互的唯一入口。它封装了所有内部子系统的复杂协调工作，提供了一个简洁、安全的 API。
-   **`CryptoHandler` (加密层):** 库的安全基石。它封装了所有密码学操作，包括使用 **Argon2id** 进行密钥派生和使用 **Fernet** 进行认证加密。它还实现了 KDF 参数的版本控制，以实现平滑的安全升级。
-   **`DataManager` (数据库层):** 负责与 `SQLite` 数据库的所有交互。所有数据库操作都是事务性的，确保了数据的一致性和原子性。
-   **`Data Formats` & `Importers` (数据格式层):** `data_formats.py` 提供了导入/导出的顶层函数。对于导入，它使用 `importers` 模块中基于**策略模式 (Strategy Pattern)** 实现的解析器。这种设计使得添加对新文件格式的支持变得非常容易，而无需修改核心分发逻辑。

---

## 😉 文件结构

项目的结构清晰且遵循 Python 社区的最佳实践。

```
oracore/
│
├── src/
│   └── oracore/
│       ├── importers/
│       │   ├── __init__.py         # 定义导入器注册表
│       │   ├── base.py             # 定义导入器的抽象基类 (策略模式)
│       │   ├── google_chrome.py    # Google Chrome CSV 导入器实现
│       │   └── samsung_pass.py     # Samsung Pass .spass 导入器实现
│       │
│       ├── __init__.py             # 使 oracore 成为一个包，并暴露公共 API
│       ├── _internal_db.py         # 数据库管理器 (私有)
│       ├── _internal_migration.py  # 数据库架构迁移逻辑 (私有)
│       ├── crypto.py               # 核心加密处理器
│       ├── data_formats.py         # 数据导入/导出函数
│       ├── exceptions.py           # 自定义异常类
│       └── vault.py                # 核心 Vault 类 (外观)
│
├── tests/                        # 单元测试
│   ├── test_crypto.py
│   ├── test_data_manager.py
│   └── test_vault.py
│
├── examples/
│   └── basic_usage.py            # 一个完整的、可运行的示例脚本
│
├── .gitignore
├── LICENSE
└── README.md
```

-   **`src/oracore/`**: 库的核心源代码。将其放在 `src` 目录下是一种现代 Python 包的标准做法，可以避免许多导入问题。
-   **`src/oracore/importers/`**: 包含所有用于解析外部文件格式的模块化导入器。
-   **`tests/`**: 包含使用 `pytest` 编写的单元测试，确保库的每个部分都按预期工作。
-   **`examples/`**: 包含如何使用该库的示例代码。

---

## 🤨 安全最佳实践 (使用者责任)

1.  **实现自动锁定**: 在用户一段时间无操作后（例如 5 分钟），自动调用 `vault.lock()`。
2.  **最小化解锁窗口**: 仅在需要访问数据时解锁，操作完成后立即锁定。
3.  **安全处理密码输入**: 在 UI 中使用密码输入框，绝不在日志或任何地方明文记录密码。
4.  **剪贴板管理**: 当用户复制密码到剪贴板后，应在短时间内（如 30 秒）自动清除。
5.  **内存安全**: `lock()` 方法会清除库内存中的密钥。请确保您的应用在操作完成后，也没有在内存中保留任何敏感数据的明文副本。
6.  **安全配置日志**: Oracore 使用 Python 的 `logging` 模块。为防止意外泄露操作信息，请确保在您的生产应用中将 Oracore 相关日志记录器的级别设置为 `INFO` 或更高。

---

## 🤗 测试与贡献

我们欢迎社区的贡献！一个完备的测试套件是确保库稳定、可靠和安全的关键。

1.  **克隆仓库**: `git clone <repository-url>`
2.  **创建虚拟环境并激活**
3.  **安装开发依赖**:
    ```bash
    # 这会以 "可编辑" 模式安装 oracore 并安装 pytest 等开发工具
    pip install -e ".[dev]"
    ```
4.  **运行测试**:
    ```bash
    pytest
    ```

---

## 😊 许可证

本项目采用 **MIT 许可证**。
