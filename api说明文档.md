好的，委员会已收到您的请求。我们将为您生成一份关于 Oracipher 项目的全面 API 与内部接口说明文档。

本文档旨在为使用者提供一份清晰、严谨的指南，详细说明了库的公共 API（推荐使用）以及为了实现特定高级功能而暴露的内部 API（应谨慎使用）。

---

### **Oracipher API & 接口说明文档**

### **核心设计哲学**

Oracipher 库遵循“高内聚，低耦合”的设计原则，并通过**外观模式 (Facade Pattern)** 提供了一个极其简洁和安全的公共接口。其核心理念是：

> **所有常规操作都应该且仅应该通过 `Vault` 类的实例来完成。**

`Vault` 对象是您与 Oracipher 安全内核交互的唯一官方入口。它负责协调内部的加密、数据库和状态管理，确保所有操作都在正确的状态下（例如，保险库已解锁）以安全的方式执行。

---

### **第一部分：公共 API (Public API)**

这是库的稳定接口，您可以放心使用。它们遵循语义化版本控制，在主版本号不变的情况下，其行为和签名将保持向后兼容。

#### **1.1 核心类: `oracipher.Vault`**

这是与保险库交互的主要入口点。

##### **初始化**

*   `Vault(data_dir: str)`
    *   **描述:** 创建一个 Vault 实例，并将其与磁盘上的一个目录绑定。如果目录不存在，它将被自动创建。
    *   **参数:**
        *   `data_dir` (`str`): 用于存储保险库数据库 (`safekey.db`) 和加密密钥文件 (`salt.key`, `verification.key`) 的目录路径。
    *   **返回:** `Vault` 类的实例。

##### **状态属性**

*   `vault.is_setup` -> `bool`
    *   **描述:** 一个只读属性，用于检查保险库是否已经被初始化（即，是否已设置主密码）。在调用 `setup()` 之前，您可以使用此属性来判断是否需要引导用户进行首次设置。
    *   **返回:** 如果保险库已设置，则为 `True`，否则为 `False`。

*   `vault.is_unlocked` -> `bool`
    *   **描述:** 一个只读属性，用于检查保险库当前是否已解锁。所有数据操作（增删改查）都要求此属性为 `True`。
    *   **返回:** 如果保险库已解锁，则为 `True`，否则为 `False`。

##### **生命周期方法**

*   `vault.setup(master_password: str) -> None`
    *   **描述:** 首次初始化保险库。此操作会生成加密盐，根据主密码派生主密钥，并创建必要的加密文件和数据库结构。
    *   **参数:**
        *   `master_password` (`str`): 用户设置的主密码。
    *   **抛出异常:**
        *   `OracipherError`: 如果保险库已经被初始化过 (`is_setup` 为 `True`)。

*   `vault.unlock(master_password: str) -> None`
    *   **描述:** 使用主密码解锁保险库。成功后，加密密钥将被加载到内存中，允许进行后续的数据操作。
    *   **参数:**
        *   `master_password` (`str`): 用于解锁的主密码。
    *   **抛出异常:**
        *   `VaultNotInitializedError`: 如果保险库尚未设置。
        *   `IncorrectPasswordError`: 如果提供的主密码错误。
        *   `CorruptDataError`: 如果加密验证文件已损坏。

*   `vault.lock() -> None`
    *   **描述:** 锁定保险库。这是一个至关重要的安全操作，它会从内存中安全地清除加密密钥，并关闭数据库连接。操作完成后，应立即调用此方法。
    *   **这是一个不会失败的安全操作。**

##### **数据操作 (CRUD) API**
*注意：以下所有方法都要求保险库处于解锁状态，否则将抛出 `VaultLockedError`。*

*   `vault.save_entry(entry_data: dict) -> int`
    *   **描述:** 保存或更新一个条目。如果 `entry_data` 字典中包含 `"id"` 键，则执行更新操作；否则，创建新条目。
    *   **参数:**
        *   `entry_data` (`dict`): 包含条目数据的字典，结构应为 `{"name": str, "category": str, "details": dict}`。更新时需包含 `"id": int`。
    *   **返回:** 被保存或更新条目的 `id`。

*   `vault.get_all_entries() -> list[dict]`
    *   **描述:** 获取保险库中的所有条目，并将它们作为一个列表加载到内存中。
    *   **返回:** 一个包含所有条目字典的列表。适用于中小型保险库。

*   `vault.get_all_entries_iter() -> Iterator[dict]`
    *   **描述:** **（推荐）** 以内存高效的迭代器（生成器）方式获取所有条目。它一次只在内存中处理一个条目，非常适合拥有大量条目的保险库。
    *   **返回:** 一个可以逐一迭代所有条目的迭代器。

*   `vault.delete_entry(entry_id: int) -> None`
    *   **描述:** 根据指定的 ID 删除一个条目。
    *   **参数:**
        *   `entry_id` (`int`): 要删除的条目的 ID。

##### **高级与危险操作**

*   `vault.change_master_password(old_password: str, new_password: str) -> None`
    *   **描述:** 更改主密码。这是一个计算密集型且至关重要的操作。它会用旧密码验证身份，然后用新密码派生的新密钥重新加密整个数据库。
    *   **参数:**
        *   `old_password` (`str`): 当前的主密码。
        *   `new_password` (`str`): 新的主密码。
    *   **抛出异常:**
        *   `VaultLockedError`: 如果保险库未解锁。
        *   `IncorrectPasswordError`: 如果 `old_password` 不正确。

*   `vault.destroy_vault() -> None`
    *   **描述:** **（警告：不可逆操作）** 永久并安全地销毁整个保险库。它会先用随机数据覆写所有文件，然后删除整个 `data_dir` 目录。
    *   **在执行此操作前，务必获得用户的明确确认。**

#### **1.2 数据格式模块: `oracipher.data_formats`**

此模块提供了用于导入和导出数据的实用函数。

*   `data_formats.export_to_csv(entries: list[dict], include_totp: bool = False) -> str`
    *   **描述:** 将条目列表导出为 CSV 格式的字符串。这是一个**不加密**的导出，用于与其他密码管理器兼容。
    *   **参数:**
        *   `entries` (`list[dict]`): 从 `vault.get_all_entries()` 获取的条目列表。
        *   `include_totp` (`bool`): 是否将 TOTP 密钥导出为 `otpauth://` URI。
    *   **返回:** CSV 格式的字符串。

*   `data_formats.import_from_file(file_path: str, file_content_bytes: bytes, password: str | None = None) -> list[dict]`
    *   **描述:** 一个高级调度函数，能自动检测文件类型（如 `.csv`, `.spass`）并调用相应的解析器。
    *   **参数:**
        *   `file_path` (`str`): 文件的完整路径（用于判断扩展名）。
        *   `file_content_bytes` (`bytes`): 文件的原始字节内容。
        *   `password` (`str | None`): 如果是加密格式（如 Samsung Pass 的 `.spass`），则需要提供密码。
    *   **返回:** 一个解析后的条目字典列表，可以用于 `vault.save_entry`。
    *   **抛出异常:**
        *   `InvalidFileFormatError`: 如果文件格式不支持或文件已损坏/密码错误。

#### **1.3 自定义异常**

这些是 `OracipherError` 的子类，允许您进行精细的错误处理。

*   `OracipherError`: 所有库异常的基类。
*   `IncorrectPasswordError`: 提供的密码不正确。
*   `VaultNotInitializedError`: 对未设置的保险库执行操作。
*   `VaultLockedError`: 对已锁定的保险库执行需要解锁的操作。
*   `CorruptDataError`: 数据（或验证文件）已损坏或被篡改。
*   `InvalidFileFormatError`: 导入的文件格式无效。

---

### **第二部分：暴露的内部 API (Exposed Internal APIs)**

以下接口虽然可以从外部访问，但它们是 Oracipher 的**内部实现细节**。

**警告：**
*   **不保证稳定性:** 这些 API 的签名和行为可能在任何次要版本更新中被更改，恕不另行通知。
*   **使用风险:** 直接使用这些 API 可能会绕过 `Vault` 类的安全和状态检查，**可能导致数据损坏、不一致或安全漏洞**。
*   **仅在您完全理解其内部工作原理并接受相关风险时才应使用它们。**

#### **2.1 `Vault` 实例的内部属性**

*   `vault._crypto` -> `CryptoHandler` 实例
    *   **描述:** `Vault` 内部用于处理所有加密操作的对象。直接调用其方法（如 `_crypto.encrypt`）会绕过 `Vault` 的 `is_unlocked` 状态检查。

*   `vault._db` -> `DataManager` 实例
    *   **描述:** `Vault` 内部用于与 SQLite 数据库交互的对象。直接调用其方法（如 `_db.save_entry`）会绕过加密层和状态管理。

#### **2.2 `oracipher.crypto.CryptoHandler` 类**

*   **描述:** 封装了所有密码学原语（Argon2id, Fernet）的类。
*   **裸露的 API 示例:**
    *   `CryptoHandler._derive_key(password: str, salt: bytes) -> bytes`
        *   **这是一个静态方法。** 它的作用是根据密码和盐，使用 Argon2id 派生出加密密钥。在 `README.md` 的旧版导入/导出示例中，它被暴露给用户来手动处理 `.skey` 文件的解密。
        *   **风险:** 直接使用它需要手动管理盐和密码，容易出错。**推荐的做法是使用更高层的 `Vault` 封装方法来进行导入/导出。**

#### **2.3 `oracipher.data_formats` 模块的内部函数**

*   `data_formats.export_to_encrypted_json(...)`
*   `data_formats.import_from_encrypted_json(...)`
    *   **描述:** 这两个函数是处理 Oracipher 自有安全格式 (`.skey`) 的核心。
    *   **风险:** 它们要求调用者手动提供 `encrypt_func` 或 `decrypt_func`，这需要直接与 `Fernet` 或 `CryptoHandler` 交互，将复杂的加密逻辑暴露给了使用者。**强烈建议通过 `Vault` 提供的封装方法来执行安全备份和恢复。**

#### **2.4 各个导入器模块 (`oracipher.importers.*`)**

*   `oracipher.importers.google_chrome.parse(file_content: str) -> list[dict]`
*   `oracipher.importers.samsung_pass.parse(file_content_bytes: bytes, password: str) -> list[dict]`
    *   **描述:** 这些是针对特定格式的专用解析器。
    *   **风险:** 直接调用它们是可行的，但 `data_formats.import_from_file` 函数提供了更高级的抽象，它能自动检测格式，是更健壮的选择。

---

### **总结与最佳实践**

1.  **坚守 `Vault`:** 始终通过 `Vault` 对象与库交互。它是为您屏蔽底层复杂性并保证安全而设计的。
2.  **遵循生命周期:** 严格遵循 `setup` (如果需要) → `unlock` → **执行操作** → `lock` 的生命周期。
3.  **使用迭代器:** 在读取大量数据时，优先使用 `get_all_entries_iter()` 以节省内存。
4.  **精细化异常处理:** 使用 `try...except` 块捕获特定的 `oracipher` 异常，为用户提供清晰的反馈（例如，“密码错误”或“文件格式无效”）。
5.  **避免内部 API:** 除非您正在为 Oracipher 开发扩展或有非常特殊的需求，否则请不要直接调用任何以下划线 (`_`) 开头的属性/方法或内部模块。