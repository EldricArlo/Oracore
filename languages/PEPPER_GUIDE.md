# 🔐 核心机密运维指南：HSC_PEPPER_HEX 管理手册

**适用版本:** Oracipher Core v1.0+
**安全等级:** 绝密 (Top Secret)

---

## ⚠️ 灾难性风险警告 (DR WARNING)

在部署 Oracipher Core 之前，运维团队**必须**理解 `HSC_PEPPER_HEX`（全局胡椒）的性质：

1.  **不可更改性 (Immutability)**: 一旦您的系统使用特定的 Pepper 加密了数据，**切勿更改它**。
    *   **后果**: 更改 Pepper 等同于丢失密钥。所有之前加密的数据（包括数据库字段、加密文件）将**永久无法解密**，导致灾难性的数据丢失。
2.  **备份必要性 (Backup Requirement)**: 
    *   **后果**: 如果服务器崩溃且 Pepper 丢失，数据将不可恢复。必须拥有异地冷备份（如纸质备份存放在保险箱）。
3.  **机密性 (Confidentiality)**:
    *   **后果**: 如果 Pepper 泄露，攻击者可以使用彩虹表或 FPGA 集群对您的数据进行暴力破解。虽然 Argon2id 提供了保护，但 Pepper 的泄露消除了“密钥哈希”带来的额外防御层。

---

## 1. 生成安全的 Pepper

Pepper 必须是 **32字节** 的高熵随机数，表示为 **64字符** 的十六进制字符串。

**推荐生成命令 (在安全的终端中运行):**
```bash
openssl rand -hex 32
```
*示例输出 (仅供参考，严禁在生产中使用):*
`8a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9`

---

## 2. 生产环境注入指南

严禁将 Pepper 硬编码在源代码、Dockerfile 或 Git 仓库中。请根据您的部署环境选择以下方案。

### 🏛️ 场景 A: Systemd 服务 (Linux 裸机/虚拟机)

在传统的 Linux 服务器上，不要将环境变量放入全局 `/etc/environment` 或用户的 `.bashrc` 中，因为这样会被所有进程看到。

**步骤:**

1.  **创建受保护的配置文件**:
    ```bash
    sudo mkdir -p /etc/oracipher
    sudo touch /etc/oracipher/pepper.env
    # 关键：设置仅 root 可读写
    sudo chmod 600 /etc/oracipher/pepper.env
    ```

2.  **写入 Pepper**:
    使用编辑器打开文件并写入：
    ```ini
    HSC_PEPPER_HEX=您的64位十六进制字符串
    ```

3.  **配置 Systemd Unit 文件**:
    在您的服务文件 (例如 `/etc/systemd/system/oracipher-app.service`) 中添加 `EnvironmentFile`:

    ```ini
    [Unit]
    Description=Oracipher Core Application
    After=network.target

    [Service]
    Type=simple
    User=www-data
    # 加载受保护的环境变量文件
    EnvironmentFile=/etc/oracipher/pepper.env
    ExecStart=/usr/local/bin/your-application
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target
    ```

---

### 🐳 场景 B: Docker (Docker Compose)

不要在 `Dockerfile` 中使用 `ENV` 指令设置 Pepper。这会将密钥永久烘焙到镜像层中，任何拉取镜像的人都能看到。

**推荐方案: 使用 Docker Secrets (即使在非 Swarm 模式下)**

1.  **创建密钥文件 (不要提交到 Git)**:
    创建文件 `secrets/pepper_hex.txt`，仅包含 Pepper 字符串。

2.  **编写 `docker-compose.yml`**:

    ```yaml
    version: '3.8'

    services:
      app:
        image: oracipher-app:latest
        environment:
          # 指示应用直接读取文件，或者使用脚本将文件内容读入环境变量
          # 如果应用支持读取文件作为配置：
          # HSC_PEPPER_FILE: /run/secrets/hsc_pepper
          # 如果应用仅支持环境变量，您需要在入口脚本中读取它
          - ...
        secrets:
          - hsc_pepper

    secrets:
      hsc_pepper:
        file: ./secrets/pepper_hex.txt
    ```

**替代方案 (仅限应用强制要求环境变量):**
在 `docker-compose.yml` 中使用 `.env` 文件注入，但**必须确保** `.env` 文件被添加到 `.gitignore` 中。

```yaml
services:
  app:
    environment:
      - HSC_PEPPER_HEX=${HSC_PEPPER_HEX}
```
*运行前: `export HSC_PEPPER_HEX=...` 或创建 `.env` 文件。*

---

### ☸️ 场景 C: Kubernetes (K8s)

在 Kubernetes 中，**绝对不要**将 Pepper 放入 `ConfigMap` 或直接写在 `Deployment` YAML 的 `env` 字段中。

**步骤:**

1.  **创建 Kubernetes Secret 对象**:
    
    ```bash
    kubectl create secret generic oracipher-keys \
      --from-literal=pepper-hex='您的64位十六进制字符串' \
      --namespace=your-namespace
    ```
    *(注意：为了避免 shell 历史记录泄露，建议使用文件创建 secret)*

2.  **在 Pod/Deployment 中挂载**:

    ```yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: oracipher-app
    spec:
      template:
        spec:
          containers:
            - name: app
              image: oracipher-app:latest
              env:
                - name: HSC_PEPPER_HEX
                  valueFrom:
                    secretKeyRef:
                      name: oracipher-keys
                      key: pepper-hex
    ```

**高级安全建议**: 对于高安全需求，建议使用 HashiCorp Vault 或 AWS Secrets Manager 配合 `ExternalSecrets` Operator 将 Pepper 动态注入到 Pod 中，并在 K8s 中启用 **Etcd Encryption at Rest**。

---

## 3. 验证与故障排查

1.  **检查加载状态**:
    应用启动后，查看日志。`Oracipher Core` 会打印加载状态：
    *   ✅ `INFO: Successfully loaded and validated the 32-byte global pepper...`
    *   ❌ `FATAL: Security pepper environment variable 'HSC_PEPPER_HEX' is not set.`

2.  **防止日志泄露**:
    **严禁** 在应用代码中打印 `HSC_PEPPER_HEX` 的具体值到日志中。Oracipher Core 内部已做好了脱敏处理，仅打印“已加载”，不打印内容。

## 4. 灾难恢复计划 (DR Plan)

1.  **纸质备份**: 将生产环境的 `HSC_PEPPER_HEX` 打印在纸上，放入信封，密封并存放在公司保险箱中。
2.  **双人控制**: 恢复密钥（纸质备份）的获取应需要两名管理员同时在场（如果安全策略要求）。

