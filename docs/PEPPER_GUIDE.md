# 🔐 Core Secret Operations Guide: HSC_PEPPER_HEX Management Manual

**Applicable Version:** Oracipher Core v5.2
**Security Level:** Top Secret
**Last Updated:** 2025-11-30

---

## ⚠️ Catastrophic Risk Warning (DR WARNING)

Before deploying Oracipher Core, the operations team **must** understand the nature of `HSC_PEPPER_HEX` (Global Pepper):

1.  **Immutability**: Once your system has encrypted data using a specific Pepper, **NEVER CHANGE IT**.
    *   **Consequence**: Changing the Pepper is equivalent to changing the master lock. All previously encrypted data (database fields, files) will be **permanently undecryptable**, resulting in total data loss.
2.  **Backup Requirement**:
    *   **Consequence**: If the server crashes and the Pepper is lost, the data is unrecoverable. You must have an off-site cold backup (e.g., a paper backup stored in a physical safe).
3.  **Confidentiality**:
    *   **Consequence**: If the Pepper is leaked, the defense-in-depth layer provided by "keyed hashing" is removed. Attackers can then use rainbow tables or FPGA clusters to attack the Argon2id hashes more efficiently.

---

## 1. Generating a Secure Pepper

The Pepper must be a **32-byte** high-entropy random number, represented as a **64-character** hexadecimal string.

**Recommended Generation Command (Run in a secure terminal):**
```bash
# Linux / macOS
openssl rand -hex 32

# Windows (PowerShell)
-join ((1..32) | ForEach-Object { "{0:x2}" -f (Get-Random -Min 0 -Max 256) })
```

*Example Output (For reference only, strictly prohibited for production use):*
`8a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9`

---

## 2. Production Environment Injection Guide

It is strictly prohibited to hardcode the Pepper in source code, Dockerfiles, or Git repositories. Please select the following scheme based on your deployment environment.

### 💎 Scenario A: Programmatic Injection (Highest Security)
**Recommended for:** Enterprise apps using HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault.

Oracipher Core v5.2 allows passing the pepper directly to the initialization function. This avoids the risk of environment variables leaking via `/proc/PID/environ` or crash dumps.

```c
// Fetch secret from your Vault client library into memory
char* secure_pepper = fetch_secret_from_vault("oracipher/prod/pepper");

// Initialize with the explicit pepper
// The library will verify length and use it immediately
if (hsc_init(NULL, secure_pepper) != HSC_OK) {
    // Handle error
}

// CRITICAL: Wipe the variable from your application memory immediately after init
sodium_memzero(secure_pepper, strlen(secure_pepper));
```

---

### 🏛️ Scenario B: Systemd Service (Linux Bare Metal/VM)

On traditional Linux servers, do not put environment variables in global profiles (`/etc/profile`).

**Steps:**

1.  **Create a protected configuration file**:
    ```bash
    sudo mkdir -p /etc/oracipher
    sudo touch /etc/oracipher/pepper.env
    # Critical: Set to read/write for root only
    sudo chmod 600 /etc/oracipher/pepper.env
    ```

2.  **Write the Pepper**:
    ```ini
    HSC_PEPPER_HEX=Your64CharacterHexString
    ```

3.  **Configure Systemd Unit File**:
    Add `EnvironmentFile` to your service definition:

    ```ini
    [Service]
    User=www-data
    # Load the protected environment variable file
    EnvironmentFile=/etc/oracipher/pepper.env
    ExecStart=/usr/local/bin/your-application
    ```

---

### 🪟 Scenario C: Windows Server (PowerShell / Service)

**Method 1: Temporary Session (Manual Run)**
For manual tasks, set the variable only for the current process scope.
```powershell
$env:HSC_PEPPER_HEX = "Your64CharacterHexString"
.\hsc_cli.exe ...
# Clear after use
Remove-Item Env:\HSC_PEPPER_HEX
```

**Method 2: Windows Service (Persistent)**
**Do not** use `setx` (it writes to the Registry in plaintext readable by users). instead, modify the Service entry in the Registry securely.

1.  Open `RegEdit`.
2.  Navigate to `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\YourServiceName`.
3.  Create/Edit a `Multi-String Value` named `Environment`.
4.  Add content: `HSC_PEPPER_HEX=Your64CharacterHexString`.
5.  **Important:** Right-click the key -> Permissions. Remove read access for non-admin users.

---

### 🐳 Scenario D: Docker (Docker Compose / Swarm)

**Challenge:** Docker Secrets mount files (e.g., `/run/secrets/my_pepper`), but Oracipher Core expects an Environment Variable or API argument.
**Solution:** Use an entrypoint script to read the file into the variable.

1.  **docker-compose.yml**:
    ```yaml
    services:
      app:
        image: oracipher-app:latest
        entrypoint: ["/bin/sh", "/entrypoint.sh"]
        secrets:
          - source: hsc_pepper_prod
            target: hsc_pepper
    
    secrets:
      hsc_pepper_prod:
        file: ./secrets/prod_pepper.txt
    ```

2.  **entrypoint.sh (Add this to your image)**:
    ```bash
    #!/bin/sh
    # Check if the secret file exists
    if [ -f /run/secrets/hsc_pepper ]; then
        # Read file content into the Environment Variable
        export HSC_PEPPER_HEX=$(cat /run/secrets/hsc_pepper)
    fi
    
    # Execute the main application
    exec "$@"
    ```

---

### ☸️ Scenario E: Kubernetes (K8s)

**Warning:** Using `env` in Deployment manifests allows anyone with `kubectl describe pod` permission to see the secret.

**Recommended:** Use `Secret` objects mapped to Environment Variables.

1.  **Create the Secret**:
    ```bash
    kubectl create secret generic oracipher-keys \
      --from-literal=pepper-hex='Your64CharacterHexString'
    ```

2.  **Deployment YAML**:
    ```yaml
    containers:
      - name: app
        env:
          - name: HSC_PEPPER_HEX
            valueFrom:
              secretKeyRef:
                name: oracipher-keys
                key: pepper-hex
    ```

**Enterprise Recommendation:** Use the **Scenario A (Programmatic Injection)** approach combined with a Sidecar (like Vault Agent) that writes the secret to a shared memory volume, which the app reads and passes to `hsc_init`.

---

## 3. Verification and Troubleshooting

1.  **Check Loading Status**:
    Check application logs (stdout/stderr). `Oracipher Core` will print:
    *   ✅ `INFO: Loading global cryptographic pepper...`
    *   ✅ `INFO: > Successfully loaded and validated the 32-byte global pepper.`
    *   ❌ `FATAL: Security pepper not provided via arguments and 'HSC_PEPPER_HEX' environment variable is not set.`

2.  **Log Hygiene**:
    *   The library is designed **NOT** to print the actual pepper value.
    *   Ensure your own application logic or debuggers do not accidentally dump the `HSC_PEPPER_HEX` variable.

## 4. Disaster Recovery Plan (DR Plan)

1.  **Physical Backup**: Print the production `HSC_PEPPER_HEX` on paper (QR code or Hex text).
2.  **Storage**: Seal it in an opaque envelope and store it in a fireproof company safe.
3.  **Recovery Drill**: Once a year, test if you can start a "Disaster Recovery" instance of the application using the key typed manually from the paper backup.
