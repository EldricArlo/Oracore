# 🔐 Core Secret Operations Guide: HSC_PEPPER_HEX Management Manual

**Applicable Version:** Oracipher Core v1.0+
**Security Level:** Top Secret

---

## ⚠️ Catastrophic Risk Warning (DR WARNING)

Before deploying Oracipher Core, the operations team **must** understand the nature of `HSC_PEPPER_HEX` (Global Pepper):

1.  **Immutability**: Once your system has encrypted data using a specific Pepper, **NEVER CHANGE IT**.
    *   **Consequence**: Changing the Pepper is equivalent to losing the key. All previously encrypted data (including database fields, encrypted files) will be **permanently undecryptable**, resulting in catastrophic data loss.
2.  **Backup Requirement**:
    *   **Consequence**: If the server crashes and the Pepper is lost, the data is unrecoverable. You must have an off-site cold backup (e.g., a paper backup stored in a safe).
3.  **Confidentiality**:
    *   **Consequence**: If the Pepper is leaked, attackers can use rainbow tables or FPGA clusters to brute-force your data. Although Argon2id provides protection, a Pepper leak eliminates the extra layer of defense provided by "keyed hashing."

---

## 1. Generating a Secure Pepper

The Pepper must be a **32-byte** high-entropy random number, represented as a **64-character** hexadecimal string.

**Recommended Generation Command (Run in a secure terminal):**
```bash
openssl rand -hex 32
```
*Example Output (For reference only, strictly prohibited for production use):*
`8a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9`

---

## 2. Production Environment Injection Guide

It is strictly prohibited to hardcode the Pepper in source code, Dockerfiles, or Git repositories. Please select the following scheme based on your deployment environment.

### 🏛️ Scenario A: Systemd Service (Linux Bare Metal/VM)

On traditional Linux servers, do not put environment variables in the global `/etc/environment` or a user's `.bashrc`, as they may be visible to all processes.

**Steps:**

1.  **Create a protected configuration file**:
    ```bash
    sudo mkdir -p /etc/oracipher
    sudo touch /etc/oracipher/pepper.env
    # Critical: Set to read/write for root only
    sudo chmod 600 /etc/oracipher/pepper.env
    ```

2.  **Write the Pepper**:
    Open the file with an editor and write:
    ```ini
    HSC_PEPPER_HEX=Your64CharacterHexString
    ```

3.  **Configure Systemd Unit File**:
    Add `EnvironmentFile` to your service file (e.g., `/etc/systemd/system/oracipher-app.service`):

    ```ini
    [Unit]
    Description=Oracipher Core Application
    After=network.target

    [Service]
    Type=simple
    User=www-data
    # Load the protected environment variable file
    EnvironmentFile=/etc/oracipher/pepper.env
    ExecStart=/usr/local/bin/your-application
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target
    ```

---

### 🐳 Scenario B: Docker (Docker Compose)

Do not use the `ENV` instruction in a `Dockerfile` to set the Pepper. This bakes the key permanently into the image layers, visible to anyone who pulls the image.

**Recommended Scheme: Use Docker Secrets (Even in non-Swarm mode)**

1.  **Create the key file (Do not commit to Git)**:
    Create a file `secrets/pepper_hex.txt` containing only the Pepper string.

2.  **Write `docker-compose.yml`**:

    ```yaml
    version: '3.8'

    services:
      app:
        image: oracipher-app:latest
        environment:
          # Instruct the app to read the file directly, or use a script to read content into env var
          # If the app supports reading a file as config:
          # HSC_PEPPER_FILE: /run/secrets/hsc_pepper
          # If the app only supports env vars, you need to read this in your entrypoint script
          - ...
        secrets:
          - hsc_pepper

    secrets:
      hsc_pepper:
        file: ./secrets/pepper_hex.txt
    ```

**Alternative (Only if application strictly mandates environment variables):**
Inject using an `.env` file in `docker-compose.yml`, but you **MUST ENSURE** the `.env` file is added to `.gitignore`.

```yaml
services:
  app:
    environment:
      - HSC_PEPPER_HEX=${HSC_PEPPER_HEX}
```
*Before running: `export HSC_PEPPER_HEX=...` or create an `.env` file.*

---

### ☸️ Scenario C: Kubernetes (K8s)

In Kubernetes, **ABSOLUTELY NEVER** put the Pepper in a `ConfigMap` or write it directly into the `env` field of a `Deployment` YAML.

**Steps:**

1.  **Create a Kubernetes Secret Object**:
    
    ```bash
    kubectl create secret generic oracipher-keys \
      --from-literal=pepper-hex='Your64CharacterHexString' \
      --namespace=your-namespace
    ```
    *(Note: To avoid shell history leaks, it is recommended to create the secret from a file)*

2.  **Mount in Pod/Deployment**:

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

**Advanced Security Recommendation**: For high-security requirements, it is recommended to use HashiCorp Vault or AWS Secrets Manager in conjunction with the `ExternalSecrets` Operator to dynamically inject the Pepper into Pods, and enable **Etcd Encryption at Rest** in K8s.

---

## 3. Verification and Troubleshooting

1.  **Check Loading Status**:
    After the application starts, check the logs. `Oracipher Core` will print the loading status:
    *   ✅ `INFO: Successfully loaded and validated the 32-byte global pepper...`
    *   ❌ `FATAL: Security pepper environment variable 'HSC_PEPPER_HEX' is not set.`

2.  **Prevent Log Leakage**:
    It is **strictly prohibited** to print the specific value of `HSC_PEPPER_HEX` into application logs. Oracipher Core has internal masking handling; it only prints "Loaded" and does not print the content.

## 4. Disaster Recovery Plan (DR Plan)

1.  **Paper Backup**: Print the production `HSC_PEPPER_HEX` on paper, place it in an envelope, seal it, and store it in the company safe.
2.  **Dual Control**: Retrieving the recovery key (paper backup) should require the simultaneous presence of two administrators (if required by security policy).