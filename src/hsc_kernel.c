/* --- START OF FILE src/hsc_kernel.c --- */

// Copyright 2025 Oracipher. All Rights Reserved.
//
// Implementation of the High-Security Core (HSC) kernel.
// This file provides the central entry points for cryptographic operations,
// key management, stream processing, and secure memory handling.

#include "hsc_kernel.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// [FIX]: 引入系统级文件控制头文件以修复权限和竞争条件问题
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/time.h>
#else
#include <windows.h>
#endif

#include <curl/curl.h>
#include <sodium.h>

#include "common/internal_logger.h"
#include "common/secure_memory.h"
#include "core_crypto/crypto_client.h"
#include "pki/pki_handler.h"

// --- Internal Opaque Structure Definitions ---

// Wrapper struct for the master key pair to maintain encapsulation.
struct hsc_master_key_pair_s {
  master_key_pair internal_kp;
};

// Wrapper struct for the crypto stream state.
struct hsc_crypto_stream_state_s {
  crypto_secretstream_xchacha20poly1305_state internal_state;
};

// --- Exported Constants ---

const uint8_t HSC_STREAM_TAG_FINAL =
    crypto_secretstream_xchacha20poly1305_TAG_FINAL;

// --- Internal Helper Functions ---

// Stores a 64-bit integer in little-endian format.
static void store64_le(unsigned char* dst, uint64_t w) {
  dst[0] = (unsigned char)w;
  w >>= 8;
  dst[1] = (unsigned char)w;
  w >>= 8;
  dst[2] = (unsigned char)w;
  w >>= 8;
  dst[3] = (unsigned char)w;
  w >>= 8;
  dst[4] = (unsigned char)w;
  w >>= 8;
  dst[5] = (unsigned char)w;
  w >>= 8;
  dst[6] = (unsigned char)w;
  w >>= 8;
  dst[7] = (unsigned char)w;
}

// Loads a 64-bit integer from little-endian format.
static uint64_t load64_le(const unsigned char* src) {
  uint64_t w = src[7];
  w = (w << 8) | src[6];
  w = (w << 8) | src[5];
  w = (w << 8) | src[4];
  w = (w << 8) | src[3];
  w = (w << 8) | src[2];
  w = (w << 8) | src[1];
  w = (w << 8) | src[0];
  return w;
}

// Internal loop to perform stream encryption from file to file.
static int _perform_stream_encryption(FILE* f_in, FILE* f_out,
                                      hsc_crypto_stream_state* st) {
  unsigned char buf_in[HSC_FILE_IO_CHUNK_SIZE];
  unsigned char buf_out[HSC_FILE_IO_CHUNK_SIZE + HSC_STREAM_CHUNK_OVERHEAD];
  size_t bytes_read;
  unsigned long long out_len;
  uint8_t tag;

  // [FIX]: 使用更安全的循环结构，避免 feof 的误用
  while ((bytes_read = fread(buf_in, 1, sizeof(buf_in), f_in)) > 0) {
    if (ferror(f_in)) {
      return HSC_ERROR_FILE_IO;
    }
    // 检查是否是最后一块
    int c = fgetc(f_in);
    if (c == EOF) {
        tag = HSC_STREAM_TAG_FINAL;
    } else {
        tag = 0;
        ungetc(c, f_in);
    }

    if (hsc_crypto_stream_push(st, buf_out, &out_len, buf_in, bytes_read,
                               tag) != HSC_OK) {
      return HSC_ERROR_CRYPTO_OPERATION;
    }
    if (fwrite(buf_out, 1, out_len, f_out) != out_len) {
      return HSC_ERROR_FILE_IO;
    }
    if (tag == HSC_STREAM_TAG_FINAL) break;
  }

  return HSC_OK;
}

// Internal loop to perform stream decryption from file to file.
// Sets stream_finished_flag to true if the final tag is successfully verified.
static int _perform_stream_decryption(FILE* f_in, FILE* f_out,
                                      hsc_crypto_stream_state* st,
                                      bool* stream_finished_flag) {
  unsigned char buf_in[HSC_FILE_IO_CHUNK_SIZE + HSC_STREAM_CHUNK_OVERHEAD];
  unsigned char buf_out[HSC_FILE_IO_CHUNK_SIZE];
  size_t bytes_read;
  unsigned long long out_len;
  unsigned char tag;
  *stream_finished_flag = false;

  while ((bytes_read = fread(buf_in, 1, sizeof(buf_in), f_in)) > 0) {
    if (ferror(f_in)) {
      return HSC_ERROR_FILE_IO;
    }

    if (hsc_crypto_stream_pull(st, buf_out, &out_len, &tag, buf_in,
                               bytes_read) != HSC_OK) {
      return HSC_ERROR_CRYPTO_OPERATION;
    }
    if (tag == HSC_STREAM_TAG_FINAL) {
      *stream_finished_flag = true;
    }
    if (fwrite(buf_out, 1, out_len, f_out) != out_len) {
      return HSC_ERROR_FILE_IO;
    }
    if (*stream_finished_flag) break;
  }

  return HSC_OK;
}

// Reads exact bytes from a key file.
static bool read_key_file(const char* filename, void* buffer,
                          size_t expected_len) {
  FILE* f = fopen(filename, "rb");
  if (!f) return false;

  fseek(f, 0, SEEK_END);
  long file_size = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (file_size < 0 || (size_t)file_size != expected_len) {
    fclose(f);
    return false;
  }

  size_t bytes_read = fread(buffer, 1, expected_len, f);
  fclose(f);

  return (bytes_read == expected_len);
}

// [FIX]: Audit Finding #2 - 强制安全文件权限
// Writes exact bytes to a key file with strictly restricted permissions (0600).
static bool write_key_file(const char* filename, const void* data, size_t len) {
#ifdef _WIN32
  // Windows implementation: Standard fopen.
  // Warning: Permissions depend on directory ACLs.
  // Administrators must disable LocalDumps via Registry.
  FILE* f = fopen(filename, "wb");
#else
  // POSIX implementation: Use open() to enforce 0600 (rw-------).
  // O_TRUNC: Truncate if exists. O_CREAT: Create if missing.
  int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
  if (fd == -1) {
      _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to open key file '%s' for writing: %s", filename, strerror(errno));
      return false;
  }
  FILE* f = fdopen(fd, "wb");
#endif

  if (!f) {
      #ifndef _WIN32
      close(fd);
      #endif
      return false;
  }
  
  bool success = (fwrite(data, 1, len, f) == len);
  fclose(f); // This also closes the underlying fd
  return success;
}

// --- API Implementation: Initialization and Cleanup ---

int hsc_init(const hsc_pki_config* config, const char* pepper_hex) {
// Disable core dumps to prevent sensitive memory leakage.
#ifndef _WIN32
  struct rlimit core_limits;
  core_limits.rlim_cur = 0;
  core_limits.rlim_max = 0;
  if (setrlimit(RLIMIT_CORE, &core_limits) != 0) {
    fprintf(stderr,
            "[Oracipher Core] FATAL: Failed to disable core dumps (errno=%d). "
            "Aborting initialization to protect secrets.\n",
            errno);
    return HSC_ERROR_GENERAL;
  }
#else
  // Windows platform security enhancements.
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  fprintf(stderr, "[Oracipher Core] SECURITY WARNING: Running on Windows.\n");
  fprintf(stderr,
          "   Ensure Windows Error Reporting (WER) is disabled or configured "
          "NOT to save LocalDumps.\n");
  fprintf(stderr,
          "   Crash dumps (.dmp files) can leak sensitive decrypted keys "
          "present in RAM to disk.\n");
#endif

  if (crypto_client_init(pepper_hex) != 0) return HSC_ERROR_CRYPTO_OPERATION;
  if (pki_init(config) != 0) return HSC_ERROR_PKI_OPERATION;
  return HSC_OK;
}

void hsc_cleanup() {
  crypto_client_cleanup();
  curl_global_cleanup();
}

void hsc_random_bytes(void* buf, size_t size) { randombytes_buf(buf, size); }

// --- API Implementation: Master Key Management ---

hsc_master_key_pair* hsc_generate_master_key_pair() {
  hsc_master_key_pair* kp = malloc(sizeof(hsc_master_key_pair));
  if (!kp) return NULL;

  kp->internal_kp.identity_sk = NULL;
  kp->internal_kp.encryption_sk = NULL;

  if (generate_master_key_pair(&kp->internal_kp) != 0) {
    hsc_free_master_key_pair(&kp);
    return NULL;
  }
  return kp;
}

hsc_master_key_pair* hsc_load_master_key_pair_from_private_key(
    const char* priv_key_path) {
  if (priv_key_path == NULL) return NULL;

  hsc_master_key_pair* kp = malloc(sizeof(hsc_master_key_pair));
  if (!kp) {
    _hsc_log(HSC_LOG_LEVEL_ERROR,
             "Failed to allocate memory for key pair structure.");
    return NULL;
  }

  kp->internal_kp.identity_sk = NULL;
  kp->internal_kp.encryption_sk = NULL;

  kp->internal_kp.identity_sk = secure_alloc(HSC_MASTER_SECRET_KEY_BYTES);
  if (!kp->internal_kp.identity_sk) {
    _hsc_log(HSC_LOG_LEVEL_ERROR,
             "Failed to allocate secure memory for identity private key.");
    free(kp);
    return NULL;
  }

  if (!read_key_file(priv_key_path, kp->internal_kp.identity_sk,
                     HSC_MASTER_SECRET_KEY_BYTES)) {
    _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to read private key file: %s",
             priv_key_path);
    hsc_free_master_key_pair(&kp);
    return NULL;
  }

  if (crypto_sign_ed25519_sk_to_pk(kp->internal_kp.identity_pk,
                                   kp->internal_kp.identity_sk) != 0) {
    _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to derive identity public key.");
    hsc_free_master_key_pair(&kp);
    return NULL;
  }

  // The sender identity key is re-introduced during encryption for signing.
  // However, the recipient still requires encryption_sk for KEM decapsulation.
  kp->internal_kp.encryption_sk = secure_alloc(crypto_box_SECRETKEYBYTES);
  if (!kp->internal_kp.encryption_sk) {
    _hsc_log(HSC_LOG_LEVEL_ERROR,
             "Failed to allocate secure memory for encryption private key.");
    hsc_free_master_key_pair(&kp);
    return NULL;
  }

  if (crypto_sign_ed25519_sk_to_curve25519(kp->internal_kp.encryption_sk,
                                           kp->internal_kp.identity_sk) != 0) {
    _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to derive encryption private key.");
    hsc_free_master_key_pair(&kp);
    return NULL;
  }

  if (crypto_sign_ed25519_pk_to_curve25519(kp->internal_kp.encryption_pk,
                                           kp->internal_kp.identity_pk) != 0) {
    _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to derive encryption public key.");
    hsc_free_master_key_pair(&kp);
    return NULL;
  }

  return kp;
}

int hsc_save_master_key_pair(const hsc_master_key_pair* kp,
                             const char* pub_key_path,
                             const char* priv_key_path) {
  if (kp == NULL || kp->internal_kp.identity_sk == NULL ||
      pub_key_path == NULL || priv_key_path == NULL) {
    return HSC_ERROR_INVALID_ARGUMENT;
  }

  // TODO(maintainer): Implement encrypted storage for private keys in future
  // versions (Priority P0). Focusing on protocol layer fixes for now.
  if (!write_key_file(pub_key_path, kp->internal_kp.identity_pk,
                      HSC_MASTER_PUBLIC_KEY_BYTES) ||
      !write_key_file(priv_key_path, kp->internal_kp.identity_sk,
                      HSC_MASTER_SECRET_KEY_BYTES)) {
    return HSC_ERROR_FILE_IO;
  }
  return HSC_OK;
}

void hsc_free_master_key_pair(hsc_master_key_pair** kp) {
  if (kp == NULL || *kp == NULL) return;
  free_master_key_pair(&(*kp)->internal_kp);
  free(*kp);
  *kp = NULL;
}

int hsc_get_master_public_key(const hsc_master_key_pair* kp,
                              unsigned char* public_key_out) {
  if (kp == NULL || public_key_out == NULL) {
    return HSC_ERROR_INVALID_ARGUMENT;
  }
  memcpy(public_key_out, kp->internal_kp.identity_pk,
         HSC_MASTER_PUBLIC_KEY_BYTES);
  return HSC_OK;
}

// --- API Implementation: PKI and Certificate Management ---

int hsc_generate_csr(const hsc_master_key_pair* mkp, const char* username,
                     char** out_csr_pem) {
  if (mkp == NULL) return HSC_ERROR_INVALID_ARGUMENT;
  return generate_csr(&mkp->internal_kp, username, out_csr_pem);
}

void hsc_free_pem_string(char* pem_string) { free_csr_pem(pem_string); }

int hsc_verify_user_certificate(const char* user_cert_pem,
                                const char* trusted_ca_cert_pem,
                                const char* expected_username) {
  return verify_user_certificate(user_cert_pem, trusted_ca_cert_pem,
                                 expected_username);
}

int hsc_extract_public_key_from_cert(const char* user_cert_pem,
                                     unsigned char* public_key_out) {
  return extract_public_key_from_cert(user_cert_pem, public_key_out);
}

// --- API Implementation: Asymmetric Encryption (Key Encapsulation) ---

// Encapsulates a session key for a recipient.
// Requires sender_mkp for signing to ensure authenticity (PFS + Auth).
int hsc_encapsulate_session_key(unsigned char* encrypted_output,
                                size_t* encrypted_output_len,
                                const unsigned char* session_key,
                                size_t session_key_len,
                                const unsigned char* recipient_pk,
                                const hsc_master_key_pair* sender_mkp) {
  if (sender_mkp == NULL) {
    return HSC_ERROR_INVALID_ARGUMENT;
  }

  // Unwrap hsc_master_key_pair and pass the internal structure.
  int result = encapsulate_session_key(encrypted_output, encrypted_output_len,
                                       session_key, session_key_len,
                                       recipient_pk, &sender_mkp->internal_kp);
  return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

// Decapsulates a session key from a sender.
// Requires sender_pk for signature verification.
int hsc_decapsulate_session_key(unsigned char* decrypted_output,
                                const unsigned char* encrypted_input,
                                size_t encrypted_input_len,
                                const hsc_master_key_pair* my_kp,
                                const unsigned char* sender_pk) {
  if (my_kp == NULL || sender_pk == NULL) {
    return HSC_ERROR_INVALID_ARGUMENT;
  }

  // Pass local decryption private key and sender public key for verification.
  int result = decapsulate_session_key(decrypted_output, encrypted_input,
                                       encrypted_input_len,
                                       my_kp->internal_kp.encryption_sk,
                                       sender_pk);
  return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

// --- API Implementation: One-shot Symmetric Encryption ---

int hsc_aead_encrypt(unsigned char* ciphertext,
                     unsigned long long* ciphertext_len,
                     const unsigned char* message, size_t message_len,
                     const unsigned char* key) {
  int result = encrypt_symmetric_aead(ciphertext, ciphertext_len, message,
                                      message_len, key);
  return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

int hsc_aead_decrypt(unsigned char* decrypted_message,
                     unsigned long long* decrypted_message_len,
                     const unsigned char* ciphertext, size_t ciphertext_len,
                     const unsigned char* key) {
  int result = decrypt_symmetric_aead(decrypted_message, decrypted_message_len,
                                      ciphertext, ciphertext_len, key);
  return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

// --- API Implementation: Streaming Encryption ---

hsc_crypto_stream_state* hsc_crypto_stream_state_new_push(
    unsigned char* header, const unsigned char* key) {
  if (header == NULL || key == NULL) return NULL;
  hsc_crypto_stream_state* state = malloc(sizeof(hsc_crypto_stream_state));
  if (state == NULL) return NULL;
  if (crypto_secretstream_xchacha20poly1305_init_push(&state->internal_state,
                                                      header, key) != 0) {
    free(state);
    return NULL;
  }
  return state;
}

hsc_crypto_stream_state* hsc_crypto_stream_state_new_pull(
    const unsigned char* header, const unsigned char* key) {
  if (header == NULL || key == NULL) return NULL;
  hsc_crypto_stream_state* state = malloc(sizeof(hsc_crypto_stream_state));
  if (state == NULL) return NULL;
  if (crypto_secretstream_xchacha20poly1305_init_pull(&state->internal_state,
                                                      header, key) != 0) {
    free(state);
    return NULL;
  }
  return state;
}

void hsc_crypto_stream_state_free(hsc_crypto_stream_state** state) {
  if (state == NULL || *state == NULL) return;
  sodium_memzero(*state, sizeof(hsc_crypto_stream_state));
  free(*state);
  *state = NULL;
}

int hsc_crypto_stream_push(hsc_crypto_stream_state* state, unsigned char* out,
                           unsigned long long* out_len,
                           const unsigned char* in, size_t in_len,
                           uint8_t tag) {
  if (state == NULL) return HSC_ERROR_INVALID_ARGUMENT;
  int result = crypto_secretstream_xchacha20poly1305_push(
      &state->internal_state, out, out_len, in, in_len, NULL, 0, tag);
  return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

int hsc_crypto_stream_pull(hsc_crypto_stream_state* state, unsigned char* out,
                           unsigned long long* out_len, unsigned char* tag,
                           const unsigned char* in, size_t in_len) {
  if (state == NULL) return HSC_ERROR_INVALID_ARGUMENT;
  int result = crypto_secretstream_xchacha20poly1305_pull(
      &state->internal_state, out, out_len, tag, in, in_len, NULL, 0);
  return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

// --- API Implementation: Advanced Hybrid Encryption (Raw Key Mode) ---

int hsc_hybrid_encrypt_stream_raw(const char* output_path,
                                  const char* input_path,
                                  const unsigned char* recipient_pk,
                                  const hsc_master_key_pair* sender_mkp) {
  if (output_path == NULL || input_path == NULL || recipient_pk == NULL ||
      sender_mkp == NULL) {
    return HSC_ERROR_INVALID_ARGUMENT;
  }
  int ret_code = HSC_ERROR_GENERAL;
  FILE* f_in = NULL;
  FILE* f_out = NULL;
  hsc_crypto_stream_state* st = NULL;
  unsigned char* session_key = NULL;
  session_key = hsc_secure_alloc(HSC_SESSION_KEY_BYTES);
  if (!session_key) {
    ret_code = HSC_ERROR_ALLOCATION_FAILED;
    goto cleanup;
  }

  // Header buffer adapts to the new HSC_MAX_ENCAPSULATED_KEY_SIZE (includes
  // signature).
  unsigned char encapsulated_key[HSC_MAX_ENCAPSULATED_KEY_SIZE];
  size_t actual_encapsulated_len;
  hsc_random_bytes(session_key, HSC_SESSION_KEY_BYTES);

  // Invoke updated encapsulation function, passing sender_mkp.
  if (hsc_encapsulate_session_key(encapsulated_key, &actual_encapsulated_len,
                                  session_key, HSC_SESSION_KEY_BYTES,
                                  recipient_pk, sender_mkp) != HSC_OK) {
    ret_code = HSC_ERROR_CRYPTO_OPERATION;
    goto cleanup;
  }
  f_in = fopen(input_path, "rb");
  if (!f_in) {
    ret_code = HSC_ERROR_FILE_IO;
    goto cleanup;
  }

  // [FIX]: Audit Finding #3 - Symlink Race / TOCTOU 防御
#ifdef _WIN32
  f_out = fopen(output_path, "wb"); // Windows 暂保留 fopen，依赖 ACL
#else
  // 使用 O_EXCL | O_CREAT 确保文件不存在，防止覆盖敏感文件（如符号链接指向的 /etc/shadow）
  // 同时应用 0600 权限
  int fd_out = open(output_path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
  if (fd_out == -1) {
      // 如果文件已存在或打开失败
      _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to open output file '%s' (O_EXCL check failed): %s", output_path, strerror(errno));
      ret_code = HSC_ERROR_FILE_IO;
      goto cleanup;
  }
  f_out = fdopen(fd_out, "wb");
#endif

  if (!f_out) {
    ret_code = HSC_ERROR_FILE_IO;
    goto cleanup;
  }
  unsigned char key_len_buf[8];
  store64_le(key_len_buf, actual_encapsulated_len);
  if (fwrite(key_len_buf, 1, sizeof(key_len_buf), f_out) !=
          sizeof(key_len_buf) ||
      fwrite(encapsulated_key, 1, actual_encapsulated_len, f_out) !=
          actual_encapsulated_len) {
    ret_code = HSC_ERROR_FILE_IO;
    goto cleanup;
  }
  unsigned char stream_header[HSC_STREAM_HEADER_BYTES];
  st = hsc_crypto_stream_state_new_push(stream_header, session_key);
  if (st == NULL) {
    ret_code = HSC_ERROR_CRYPTO_OPERATION;
    goto cleanup;
  }
  if (fwrite(stream_header, 1, sizeof(stream_header), f_out) !=
      sizeof(stream_header)) {
    ret_code = HSC_ERROR_FILE_IO;
    goto cleanup;
  }
  ret_code = _perform_stream_encryption(f_in, f_out, st);
  if (ret_code != HSC_OK) {
    goto cleanup;
  }
  ret_code = HSC_OK;
cleanup:
  if (f_in) fclose(f_in);
  if (f_out) fclose(f_out);
  if (ret_code != HSC_OK && output_path != NULL) remove(output_path);
  hsc_crypto_stream_state_free(&st);
  hsc_secure_free(session_key);
  return ret_code;
}

int hsc_hybrid_decrypt_stream_raw(const char* output_path,
                                  const char* input_path,
                                  const hsc_master_key_pair* recipient_kp,
                                  const unsigned char* sender_pk) {
  if (output_path == NULL || input_path == NULL || recipient_kp == NULL ||
      sender_pk == NULL) {
    return HSC_ERROR_INVALID_ARGUMENT;
  }
  int ret_code = HSC_ERROR_GENERAL;
  FILE* f_in = NULL;
  FILE* f_out = NULL;
  hsc_crypto_stream_state* st = NULL;
  unsigned char* encapsulated_key = NULL;
  unsigned char* dec_session_key = NULL;
  f_in = fopen(input_path, "rb");
  if (!f_in) {
    ret_code = HSC_ERROR_FILE_IO;
    goto cleanup;
  }
  unsigned char key_len_buf[8];
  if (fread(key_len_buf, 1, sizeof(key_len_buf), f_in) != sizeof(key_len_buf)) {
    ret_code = HSC_ERROR_INVALID_FORMAT;
    goto cleanup;
  }
  size_t enc_key_len = load64_le(key_len_buf);
  if (enc_key_len == 0 || enc_key_len > HSC_MAX_ENCAPSULATED_KEY_SIZE) {
    ret_code = HSC_ERROR_INVALID_FORMAT;
    goto cleanup;
  }
  encapsulated_key = hsc_secure_alloc(enc_key_len);
  if (!encapsulated_key) {
    ret_code = HSC_ERROR_ALLOCATION_FAILED;
    goto cleanup;
  }
  if (fread(encapsulated_key, 1, enc_key_len, f_in) != enc_key_len) {
    ret_code = HSC_ERROR_INVALID_FORMAT;
    goto cleanup;
  }
  dec_session_key = hsc_secure_alloc(HSC_SESSION_KEY_BYTES);
  if (!dec_session_key) {
    ret_code = HSC_ERROR_ALLOCATION_FAILED;
    goto cleanup;
  }

  // Invoke updated decapsulation function, passing sender_pk for signature
  // verification.
  if (hsc_decapsulate_session_key(dec_session_key, encapsulated_key,
                                  enc_key_len, recipient_kp,
                                  sender_pk) != HSC_OK) {
    ret_code = HSC_ERROR_CRYPTO_OPERATION;
    goto cleanup;
  }
  unsigned char stream_header[HSC_STREAM_HEADER_BYTES];
  if (fread(stream_header, 1, sizeof(stream_header), f_in) !=
      sizeof(stream_header)) {
    ret_code = HSC_ERROR_INVALID_FORMAT;
    goto cleanup;
  }
  st = hsc_crypto_stream_state_new_pull(stream_header, dec_session_key);
  if (st == NULL) {
    ret_code = HSC_ERROR_CRYPTO_OPERATION;
    goto cleanup;
  }

  // [FIX]: 应用 O_EXCL 保护解密输出流，防止覆盖攻击
#ifdef _WIN32
  f_out = fopen(output_path, "wb");
#else
  int fd_out = open(output_path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
  if (fd_out == -1) {
      _hsc_log(HSC_LOG_LEVEL_ERROR, "Failed to open output file '%s' (O_EXCL check failed): %s", output_path, strerror(errno));
      ret_code = HSC_ERROR_FILE_IO;
      goto cleanup;
  }
  f_out = fdopen(fd_out, "wb");
#endif

  if (!f_out) {
    ret_code = HSC_ERROR_FILE_IO;
    goto cleanup;
  }
  bool stream_finished = false;
  ret_code = _perform_stream_decryption(f_in, f_out, st, &stream_finished);
  if (ret_code != HSC_OK) {
    goto cleanup;
  }
  if (!stream_finished) {
    ret_code = HSC_ERROR_INVALID_FORMAT;
    goto cleanup;
  }
  ret_code = HSC_OK;
cleanup:
  if (f_in) fclose(f_in);
  if (f_out) fclose(f_out);
  if (ret_code != HSC_OK && output_path != NULL) remove(output_path);
  hsc_secure_free(encapsulated_key);
  hsc_crypto_stream_state_free(&st);
  hsc_secure_free(dec_session_key);
  return ret_code;
}

// --- API Implementation: Secure Memory Management ---

void* hsc_secure_alloc(size_t size) { return secure_alloc(size); }

void hsc_secure_free(void* ptr) { secure_free(ptr); }

// --- API Implementation: Log Callback Management ---

static hsc_log_callback g_log_callback = NULL;

void hsc_set_log_callback(hsc_log_callback callback) {
  g_log_callback = callback;
}

#define HSC_LOG_BUFFER_SIZE 2048

void _hsc_log(int level, const char* format, ...) {
  if (g_log_callback == NULL) {
    return;
  }

  char buffer[HSC_LOG_BUFFER_SIZE];

  va_list args;
  va_start(args, format);
  // Note: Log messages may be truncated if they exceed the buffer size.
  // Callers should be aware of this limitation.
  vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);

  g_log_callback(level, buffer);
}

// =======================================================================
// --- Expert API Implementation ---
// =======================================================================

int hsc_derive_key_from_password(unsigned char* derived_key,
                                 size_t derived_key_len, const char* password,
                                 const unsigned char* salt) {
  if (derived_key == NULL || password == NULL || salt == NULL) {
    return HSC_ERROR_INVALID_ARGUMENT;
  }

  size_t pepper_len = 0;
  const unsigned char* pepper = get_global_pepper(&pepper_len);
  if (pepper == NULL || pepper_len == 0) {
    _hsc_log(HSC_LOG_LEVEL_ERROR,
             "FATAL: Global pepper is not available. Was hsc_init() called and "
             "successful?");
    return HSC_ERROR_GENERAL;
  }

  int result =
      derive_key_from_password(derived_key, derived_key_len, password, salt,
                               g_argon2_opslimit, g_argon2_memlimit, pepper, pepper_len);
  return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

int hsc_convert_ed25519_pk_to_x25519_pk(unsigned char* x25519_pk_out,
                                        const unsigned char* ed25519_pk_in) {
  if (x25519_pk_out == NULL || ed25519_pk_in == NULL) {
    return HSC_ERROR_INVALID_ARGUMENT;
  }
  if (crypto_sign_ed25519_pk_to_curve25519(x25519_pk_out, ed25519_pk_in) != 0) {
    return HSC_ERROR_CRYPTO_OPERATION;
  }
  return HSC_OK;
}

int hsc_convert_ed25519_sk_to_x25519_sk(unsigned char* x25519_sk_out,
                                        const unsigned char* ed25519_sk_in) {
  if (x25519_sk_out == NULL || ed25519_sk_in == NULL) {
    return HSC_ERROR_INVALID_ARGUMENT;
  }
  if (crypto_sign_ed25519_sk_to_curve25519(x25519_sk_out, ed25519_sk_in) != 0) {
    return HSC_ERROR_CRYPTO_OPERATION;
  }
  return HSC_OK;
}

int hsc_aead_encrypt_detached_safe(unsigned char* ciphertext,
                                   unsigned char* tag_out,
                                   unsigned char* nonce_out,
                                   const unsigned char* message,
                                   size_t message_len,
                                   const unsigned char* additional_data,
                                   size_t ad_len, const unsigned char* key) {
  if (ciphertext == NULL || tag_out == NULL || nonce_out == NULL ||
      message == NULL || key == NULL) {
    return HSC_ERROR_INVALID_ARGUMENT;
  }

  hsc_random_bytes(nonce_out, HSC_AEAD_NONCE_BYTES);

  int result = encrypt_symmetric_aead_detached(
      ciphertext, tag_out, message, message_len, additional_data, ad_len,
      nonce_out, key);

  return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}

int hsc_aead_decrypt_detached(unsigned char* decrypted_message,
                              const unsigned char* ciphertext,
                              size_t ciphertext_len, const unsigned char* tag,
                              const unsigned char* additional_data,
                              size_t ad_len, const unsigned char* nonce,
                              const unsigned char* key) {
  if (decrypted_message == NULL || ciphertext == NULL || tag == NULL ||
      nonce == NULL || key == NULL) {
    return HSC_ERROR_INVALID_ARGUMENT;
  }
  int result = decrypt_symmetric_aead_detached(
      decrypted_message, ciphertext, ciphertext_len, tag, additional_data,
      ad_len, nonce, key);
  return (result == 0) ? HSC_OK : HSC_ERROR_CRYPTO_OPERATION;
}
/* --- END OF FILE src/hsc_kernel.c --- */