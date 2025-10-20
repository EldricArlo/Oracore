# Oracipher: 一个强大、安全且现代的 Python 密码库核心

[![PyPI Version](https://img.shields.io/pypi/v/oracipher.svg)](https://pypi.org/project/oracipher/)
[![Python Tests](https://github.com/EldricArlo/OraciCore/actions/workflows/python-package.yml/badge.svg)](https://github.com/EldricArlo/OraciCore/actions/workflows/python-package.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Oracipher** 是一个为构建高性能、高安全性的本地密码管理器而设计的独立 Python 核心库。它将复杂的密码学操作、安全的数据库管理和灵活的数据格式处理封装在一个简洁、健壮且开发者友好的 API 之后。

---

## 🌟 为什么选择 Oracipher？

| 特性 | 描述 |
| :--- | :--- |
| 🛡️ **极致安全** | **安全是我们设计的基石，而非事后补充。** 我们采用行业黄金标准 **Argon2id** 进行密钥派生，使用 **Fernet (AES + HMAC)** 进行认证加密，并通过**常量时间比较**等最佳实践，从源头上杜绝时序攻击等常见漏洞。 |
| 🏛️ **现代架构** | **简洁的 API，强大的内核。** 通过优雅的**外观模式 (Facade)**，您只需与一个 `Vault` 对象交互。底层的高度模块化和**事务性数据库**操作，确保了代码的健壮性、可维护性和数据一致性。 |
| ⚡ **性能卓越** | **轻松应对海量数据。** Oracipher 提供了基于**生成器**的高效 API (`get_all_entries_iter`)，即使面对包含数万条记录的密码库，也能保持极低的内存占用和流畅的性能。 |
| ✍️ **开发者友好** | **专注于您的应用逻辑，而非底层复杂性。** 完整的 **Python 类型提示**、精确的**自定义异常体系**以及灵活的**数据导入/导出**工具，为您提供了清晰、可预测且愉悦的开发体验。 |

## 📦 安装

在您的项目虚拟环境中通过 `pip` 安装 Oracipher：

```bash
pip install oracipher
```

## 🚀 快速上手：保险库 (Vault) 的生命周期

与 Oracipher 的所有交互都通过 `Vault` 对象进行。正确使用它需要遵循一个简单而严格的生命周期：**设置 (Setup) → 解锁 (Unlock) → 使用 (Use) → 锁定 (Lock)**。

以下是一个完整且健壮的典型用法示例：

```python
import os
from oracipher import Vault, OracipherError, IncorrectPasswordError

# 1. 定义保险库文件的存储位置
data_directory = "./my_secure_vault"
vault = Vault(data_directory)
master_password = "my-super-secret-password-!@#" # 应从用户界面安全地获取

try:
    # 2. [设置] 检查保险库是否首次使用
    if not vault.is_setup:
        print("Vault not found. Setting it up now...")
        vault.setup(master_password)
        print("Vault setup complete.")

    # 3. [解锁] 对保险库进行任何操作前都必须解锁
    vault.unlock(master_password)
    print("Vault unlocked successfully!")

    # --- 4. [使用] 在解锁后执行所有操作 ---
    
    # a. 保存一个新的登录条目
    new_entry_id = vault.save_entry({
        "name": "GitHub",
        "category": "Development",
        "details": {
            "username": "my_username",
            "password": "a_very_strong_password_generated",
            "url": "github.com",
            "notes": "Work account"
        }
    })
    print(f"Saved new entry with ID: {new_entry_id}")

    # b. 高效地遍历所有条目
    print("\nEntries in vault:")
    for entry in vault.get_all_entries_iter(): # 推荐使用内存高效的迭代器
        print(f"- ID: {entry['id']}, Name: {entry['name']}")

except IncorrectPasswordError:
    print("Error: The master password was incorrect.")
except OracipherError as e:
    # 捕获所有其他 Oracipher 特定错误
    print(f"A vault-related error occurred: {e}")
except Exception as e:
    print(f"An unexpected system error occurred: {e}")
finally:
    # 5. [锁定] [至关重要] 无论发生什么，都要确保在操作结束后锁定保险库
    if vault.is_unlocked:
        vault.lock()
        print("\nVault has been securely locked.")
```

## 📚 API 详解

### `Vault` 核心 API

#### 状态属性
*   `vault.is_setup` -> `bool`: 检查保险库是否已被初始化。
*   `vault.is_unlocked` -> `bool`: 检查保险库当前是否已解锁。

#### 生命周期方法
*   `vault.setup(master_password: str)`: 首次创建保险库。
*   `vault.unlock(master_password: str)`: 解锁保险库。
*   `vault.lock()`: 锁定保险库，从内存中安全清除密钥。

#### 数据操作 (CRUD)
> **注意:** 以下所有方法都要求保险库处于**已解锁**状态，否则将抛出 `VaultLockedError`。

*   `vault.save_entry(entry_data: dict) -> int`: 保存或更新一个条目。
*   `vault.get_all_entries() -> list[dict]`: 获取所有条目并存入一个列表。
*   `vault.get_all_entries_iter() -> Iterator[dict]`: **（推荐）** 以内存高效的迭代器方式获取所有条目。
*   `vault.delete_entry(entry_id: int)`: 根据 ID 删除一个条目。

#### 数据导入与导出
*   `vault.export_to_skey(export_path: str)`: **[新增]** 安全地将整个保险库导出到加密的 `.skey` 文件。
*   `Vault.import_from_skey(skey_path: str, backup_password: str, target_vault: Vault)`: **[新增]** 将 `.skey` 备份文件中的条目导入到已解锁的目标保险库中。

#### 高级与危险操作
*   `vault.change_master_password(old_password: str, new_password: str)`: 更改主密码。
*   `vault.destroy_vault()`: **（警告：不可逆）** 安全地销毁整个保险库。

### 数据导入与导出

#### [修改] 安全备份与恢复 (`.skey` 格式)

这是在不同设备间迁移或备份保险库的**推荐方式**。所有复杂操作现已封装在 `Vault` API 内部。

```python
from oracipher import Vault, InvalidFileFormatError

# --- 1. 安全导出 (vault 必须已解锁) ---
try:
    if vault.is_unlocked:
        backup_path = "my_secure_backup.skey"
        vault.export_to_skey(backup_path)
        print(f"✅ Secure backup created at: {backup_path}")
except Exception as e:
    print(f"❌ Export failed: {e}")

# --- 2. 安全导入 (target_vault 必须已解锁) ---
# 假设我们有一个新的或已存在的已解锁保险库 target_vault
# backup_password 是创建备份文件时所使用的主密码

try:
    # 静态方法 Vault.import_from_skey 处理所有解密和导入逻辑
    Vault.import_from_skey(
        skey_path="my_secure_backup.skey",
        backup_password="the-password-used-for-the-backup",
        target_vault=vault # 导入到当前 vault
    )
    print("✅ Successfully imported entries from backup.")
except InvalidFileFormatError as e:
    print(f"❌ Import failed: Incorrect password or corrupt file. Details: {e}")
except Exception as e:
    print(f"❌ An unexpected error occurred during import: {e}")

```

#### 其他格式

位于 `oracipher.data_formats` 模块的函数可用于处理非加密格式。

*   `data_formats.export_to_csv(entries: list) -> str`: 导出为 CSV 字符串。
*   `data_formats.import_from_file(file_path: str, file_content_bytes: bytes) -> list`: 从通用 CSV, TXT 等文件导入。

## ⚠️ 安全最佳实践 (使用者责任)

1.  **实现自动锁定**: 在用户一段时间无操作后（例如 5 分钟），自动调用 `vault.lock()`。
2.  **最小化解锁窗口**: 仅在需要访问数据时解锁，操作完成后立即锁定。
3.  **安全处理密码输入**: 在 UI 中使用密码输入框，绝不在日志或任何地方明文记录密码。
4.  **剪贴板管理**: 当用户复制密码到剪贴板后，应在短时间内（如 30 秒）自动清除。
5.  **内存安全**: `lock()` 方法会清除库内存中的密钥。请确保您的应用在操作完成后，也没有在内存中保留任何敏感数据的明文副本。
6.  **[新增] 安全配置日志**: Oracipher 使用 Python 的 `logging` 模块。为防止意外泄露操作信息，请确保在您的生产应用中将 Oracipher 相关日志记录器的级别设置为 `INFO` 或更高。

## 🏛️ 架构概览
```
  [您的应用程序]
       │
       ▼
┌────────────────┐
│   Vault (外观)   │  <-- 唯一的公共交互入口
└────────────────┘
       │
       ├─────────────► ┌──────────────────┐
       │             │ CryptoHandler    │ (负责所有加密操作)
       │             └──────────────────┘
       │
       ├─────────────► ┌──────────────────┐
       │             │ DataManager      │ (负责数据库交互)
       │             └──────────────────┘
       │
       └─────────────► ┌──────────────────┐
                     │ Data Formats     │ (负责导入/导出)
                     └──────────────────┘
```
*   **`Vault` (外观层):** 协调所有底层组件，提供简洁、安全的 API。
*   **`CryptoHandler` (加密层):** 安全基石，封装所有密码学操作。
*   **`DataManager` (数据库层):** 负责与 `SQLite` 的事务性交互。
*   **`Data Formats` (数据格式层):** 独立的工具，处理数据的序列化与解析。

## 🧪 测试与贡献

我们欢迎社区的贡献！一个完备的测试套件是确保库稳定、可靠和安全的关键。

1.  **克隆仓库**: `git clone <repository-url>`
2.  **创建虚拟环境并激活**
3.  **安装开发依赖**:
    ```bash
    pip install -e ".[dev]"
    ```
4.  **运行测试**:
    ```bash
    pytest
    ```

## 📜 许可证

本项目采用 **MIT 许可证**。