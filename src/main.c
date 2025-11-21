/* --- START OF FILE src/main.c --- */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

#include "hsc_kernel.h"
// 引入 sodium.h 以使用 sodium_memcmp 进行安全比较
#include <sodium.h>

// --- 辅助函数 ---
void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// 从文件中读取PEM字符串的辅助函数
char* read_pem_file(const char* filename) {
    // [FIX]: Mitigation for Finding #3 - Windows ftell overflow risk
    // 使用二进制模式打开，并增加简单的文件大小检查防止 DoS
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "\n错误: 无法打开演示所需的PEM文件 '%s'。\n", filename);
        fprintf(stderr, "请确保您已按照README中的说明，使用'test_ca_util'工具生成了所有必需的证书文件。\n");
        return NULL;
    }
    
    fseek(f, 0, SEEK_END);
    long long length = 0;
    #ifdef _WIN32
        length = _ftelli64(f);
    #else
        length = ftell(f);
    #endif
    
    fseek(f, 0, SEEK_SET);
    
    // [FIX]: Finding #4 - DoS Protection
    // 限制最大读取大小为 1MB
    if (length <= 0 || length > 1024 * 1024) { 
        fprintf(stderr, "错误: 文件大小无效或过大 (DoS 保护限制)。\n");
        fclose(f); 
        return NULL; 
    }

    char* buffer = malloc((size_t)length + 1);
    if (!buffer) { fclose(f); return NULL; }
    
    if (fread(buffer, 1, (size_t)length, f) != (size_t)length) {
        fclose(f);
        free(buffer);
        return NULL;
    }
    buffer[length] = '\0';
    fclose(f);
    return buffer;
}


// --- 主演示程序 ---
int main() {
    printf("--- Oracipher Core v5.1 (Auth+PFS) 内核库API演示 ---\n");
    printf("此程序演示了作为库客户端的端到端工作流 (Authenticated Ephemeral KEM)。\n");
    printf("它假定CA证书和用户证书已由一个独立的CA工具生成。\n\n");
    
    int ret = 1;

    // --- 声明所有需要清理的资源 ---
    hsc_master_key_pair* alice_mkp = NULL;
    char* ca_cert_pem = NULL;
    char* alice_cert_pem = NULL;
    unsigned char* encrypted_file = NULL;
    unsigned char* encapsulated_session_key = NULL;
    unsigned char* decrypted_session_key = NULL;
    unsigned char* decrypted_file_content = NULL;

    // --- 初始化 ---
    // 传入 NULL, NULL 以使用默认安全配置和 ENV Pepper
    if (hsc_init(NULL, NULL) != HSC_OK) {
        fprintf(stderr, "错误: 高安全内核库初始化失败！\n");
        goto cleanup;
    }
    printf("密码学库初始化成功。\n\n");

    // --- 阶段一: 'Alice' 创建本地密钥对 ---
    printf("--- 阶段一: 'Alice' 创建她的主密钥对 ---\n");
    const char* alice_username = "alice@example.com";
    
    alice_mkp = hsc_generate_master_key_pair();
    if (alice_mkp == NULL) {
        fprintf(stderr, "错误: 生成 Alice 的主密钥对失败。\n");
        goto cleanup;
    }
    printf("'Alice' 的主密钥对已在内存中生成。\n\n");
    
    // --- 加载由外部CA工具生成的证书 ---
    printf("--- 阶段二: 加载由外部CA签发的证书文件 ---\n");
    ca_cert_pem = read_pem_file("ca.pem");
    alice_cert_pem = read_pem_file("alice.pem");
    if (!ca_cert_pem || !alice_cert_pem) {
        goto cleanup; // read_pem_file 内部已打印错误信息
    }
    printf("成功加载 'ca.pem' 和 'alice.pem'。\n\n");


    // --- 阶段三: 端到端文件加密与安全共享 (Alice 加密文件并分享给自己) ---
    printf("--- 阶段三: 端到端共享演示 (Alice -> Alice) ---\n");

    // 1. 本地加密 (生成会话密钥，用AEAD加密文件内容)
    printf("1. 本地文件加密...\n");
    unsigned char session_key[HSC_SESSION_KEY_BYTES];
    hsc_random_bytes(session_key, sizeof(session_key));
    print_hex("  > [明文] 会话密钥", session_key, sizeof(session_key));
    
    const char* file_content = "这是文件的机密内容。This is the secret content of the file.";
    printf("  > [明文] 文件内容: \"%s\"\n", file_content);
    
    size_t file_content_len = strlen(file_content);
    size_t enc_file_buf_len = file_content_len + HSC_AEAD_OVERHEAD_BYTES;
    
    encrypted_file = hsc_secure_alloc(enc_file_buf_len);
    if (!encrypted_file) { fprintf(stderr, "安全内存分配失败！\n"); goto cleanup; }
    unsigned long long actual_enc_file_len;
    
    if (hsc_aead_encrypt(encrypted_file, &actual_enc_file_len, (unsigned char*)file_content, file_content_len, session_key) != HSC_OK) {
        fprintf(stderr, "严重错误: 对称加密文件失败！\n"); goto cleanup;
    }
    printf("  > 文件内容已使用 AEAD 对称加密。\n\n");
    
    // 2. 验证接收者 ('Alice') 的证书
    printf("2. 验证接收者 ('Alice') 的证书...\n");
    if (hsc_verify_user_certificate(alice_cert_pem, ca_cert_pem, alice_username) != HSC_OK) {
        fprintf(stderr, "严重错误: 接收者证书验证失败！中止共享。\n");
        goto cleanup;
    }
    printf("  > 接收者证书验证成功！\n\n");
    
    // 3. 从证书中提取接收者公钥 (用于加密)
    printf("3. 从证书中提取接收者公钥...\n");
    unsigned char recipient_pk[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert(alice_cert_pem, recipient_pk) != HSC_OK) {
        fprintf(stderr, "严重错误: 无法从证书中提取公钥！\n"); goto cleanup;
    }
    print_hex("  > 提取到的接收者公钥", recipient_pk, sizeof(recipient_pk));
    printf("\n");

    // 4. 封装会话密钥 (Authenticated Ephemeral KEM)
    printf("4. 为接收者封装会话密钥 (使用 Authenticated Ephemeral KEM)...\n");
    size_t encapsulated_key_buf_len = HSC_MAX_ENCAPSULATED_KEY_SIZE;
    
    encapsulated_session_key = hsc_secure_alloc(encapsulated_key_buf_len);
    if (!encapsulated_session_key) { fprintf(stderr, "安全内存分配失败！\n"); goto cleanup; }
    
    size_t actual_encapsulated_len;
    
    // [FIX]: API Update - 传入 sender_mkp (Alice) 用于签名
    if (hsc_encapsulate_session_key(encapsulated_session_key, &actual_encapsulated_len, 
                                    session_key, sizeof(session_key),
                                    recipient_pk,
                                    alice_mkp) != HSC_OK) {
        fprintf(stderr, "严重错误: 封装会话密钥失败！\n"); goto cleanup;
    }
    printf("  > 会话密钥已使用非对称加密封装，并由发送者签名。\n\n");
    
    // --- 阶段四: 作为接收者解密 ---
    printf("--- 阶段四: 作为接收者 'Alice' 解密文件 ---\n");

    // [模拟] 接收方首先需要知道发送方是谁，并获取其公钥
    // 在这个演示中，发送方就是 Alice 自己，所以我们从 Alice 的证书中提取公钥用于验签
    unsigned char sender_public_key[HSC_MASTER_PUBLIC_KEY_BYTES];
    if (hsc_extract_public_key_from_cert(alice_cert_pem, sender_public_key) != HSC_OK) {
        fprintf(stderr, "严重错误: 无法获取发送者公钥！\n"); goto cleanup;
    }

    // 1. 解封装会话密钥
    printf("1. 解封装会话密钥 (验证签名)...\n");
    decrypted_session_key = hsc_secure_alloc(sizeof(session_key));
    if (!decrypted_session_key) { fprintf(stderr, "安全内存分配失败！\n"); goto cleanup; }

    // [FIX]: API Update - 传入 sender_public_key 用于验签
    if (hsc_decapsulate_session_key(decrypted_session_key, 
                                    encapsulated_session_key, actual_encapsulated_len, 
                                    alice_mkp,
                                    sender_public_key) != HSC_OK) {
        fprintf(stderr, "解密错误: 无法解封装会话密钥 (签名验证失败？)！\n"); goto cleanup;
    }
    print_hex("  > [解密] 恢复的会话密钥", decrypted_session_key, sizeof(session_key));

    if (sodium_memcmp(session_key, decrypted_session_key, sizeof(session_key)) != 0) {
        fprintf(stderr, "验证失败: 恢复的会话密钥与原始密钥不匹配！\n");
        goto cleanup;
    }
    printf("  > 验证成功: 恢复的会话密钥与原始密钥匹配。\n\n");

    // 2. 使用恢复的会话密钥解密文件内容
    printf("2. 使用恢复的会话密钥解密文件内容...\n");
    
    decrypted_file_content = hsc_secure_alloc(file_content_len + 1);
    if (!decrypted_file_content) { fprintf(stderr, "安全内存分配失败！\n"); goto cleanup; }
    unsigned long long actual_dec_file_len;
    
    if (hsc_aead_decrypt(decrypted_file_content, &actual_dec_file_len, encrypted_file, actual_enc_file_len, decrypted_session_key) != HSC_OK) {
        fprintf(stderr, "解密错误: 无法解密文件内容！\n");
        goto cleanup;
    }
    decrypted_file_content[actual_dec_file_len] = '\0';
    
    printf("  > [解密] 恢复的文件内容: \"%s\"\n", (char*)decrypted_file_content);

    if (actual_dec_file_len == file_content_len &&
        sodium_memcmp(file_content, decrypted_file_content, file_content_len) == 0) 
    {
        printf("  > 验证成功: 恢复的文件内容与原始内容匹配。\n\n");
    } else {
        printf("  > 验证失败: 恢复的文件内容与原始内容不匹配！\n\n");
        goto cleanup;
    }
    
    ret = 0; 
    printf("\033[32m--- 演示成功完成 ---\033[0m\n");

cleanup:
    printf("\n--- 清理所有资源 ---\n");
    free(ca_cert_pem);
    free(alice_cert_pem);
    hsc_free_master_key_pair(&alice_mkp);
    
    if (encrypted_file) hsc_secure_free(encrypted_file);
    if (encapsulated_session_key) hsc_secure_free(encapsulated_session_key);
    if (decrypted_session_key) hsc_secure_free(decrypted_session_key);
    if (decrypted_file_content) hsc_secure_free(decrypted_file_content);

    hsc_cleanup();
    printf("清理完成。\n");

    return ret;
}
/* --- END OF FILE src/main.c --- */