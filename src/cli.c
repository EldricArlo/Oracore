// Copyright 2025 Oracipher Core.
//
// Oracipher Core Command Line Interface (CLI).
// 
// [Refactored]: Transformed from a static demo into a functional CLI tool.
// This file implements the user interface for key management and enforces
// safe file handling policies (Anti-Overwrite).

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>

// [FIX]: Include headers for file access checks
#ifdef _WIN32
    #include <io.h>
    #define R_OK 4
    #define access _access
#else
    #include <unistd.h>
#endif

#include "hsc_kernel.h"
#include <sodium.h>

// --- Helper Functions (Preserved for future extensions) ---

void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

char* read_pem_file(const char* filename) {
    FILE* f = fopen(filename, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (length <= 0 || length > 1024 * 1024) { 
        fclose(f); 
        return NULL; 
    }

    char* buffer = malloc((size_t)length + 1);
    if (!buffer) { fclose(f); return NULL; }
    
    if (fread(buffer, 1, (size_t)length, f) != (size_t)length) {
        fclose(f); free(buffer); return NULL;
    }
    buffer[length] = '\0';
    fclose(f);
    return buffer;
}

// --- CLI Helper Functions ---

void print_usage(const char* prog_name) {
    printf("Oracipher Core CLI v5.1\n");
    printf("Usage: %s <command> [options]\n\n", prog_name);
    printf("Commands:\n");
    printf("  gen-keypair <name> [--force]\n");
    printf("      Generate a new master key pair.\n");
    printf("      Output: <name>.key (Private) and <name>.pub (Public)\n");
    printf("      --force: Overwrite existing files if they exist.\n");
    printf("\n");
    printf("  help\n");
    printf("      Show this help message.\n");
}

bool file_exists(const char* filename) {
    if (access(filename, R_OK) == 0) {
        return true;
    }
    return false;
}

// --- Command Implementation: gen-keypair ---

// [FIX]: Implements safe key generation with --force logic
int cmd_gen_keypair(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Error: Missing key name.\n");
        fprintf(stderr, "Usage: gen-keypair <name> [--force]\n");
        return 1;
    }

    const char* name = argv[1];
    bool force = false;

    // Parse options starting from argv[2]
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--force") == 0) {
            force = true;
        } else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            return 1;
        }
    }

    char pub_path[512];
    char priv_path[512];
    
    // Construct filenames
    if (snprintf(pub_path, sizeof(pub_path), "%s.pub", name) >= (int)sizeof(pub_path) ||
        snprintf(priv_path, sizeof(priv_path), "%s.key", name) >= (int)sizeof(priv_path)) {
        fprintf(stderr, "Error: Key name is too long.\n");
        return 1;
    }

    // [FIX]: Check for existing files (Pre-flight check)
    bool pub_exists = file_exists(pub_path);
    bool priv_exists = file_exists(priv_path);

    if (pub_exists || priv_exists) {
        if (!force) {
            // [FAIL-SAFE]: If files exist and --force is NOT set, abort.
            fprintf(stderr, "\n[SECURITY ERROR] Key files already exist:\n");
            if (pub_exists) fprintf(stderr, "  - %s\n", pub_path);
            if (priv_exists) fprintf(stderr, "  - %s\n", priv_path);
            fprintf(stderr, "Operation aborted to prevent accidental overwrite.\n");
            fprintf(stderr, "Use '--force' if you intend to replace them.\n");
            return 1;
        } else {
            // [FORCE]: User explicitly requested overwrite.
            // Since kernel uses O_EXCL, we must manually remove old files first.
            printf("Warning: --force specified. Removing existing keys...\n");
            if (pub_exists && remove(pub_path) != 0) {
                fprintf(stderr, "Error: Failed to delete '%s': %s\n", pub_path, strerror(errno));
                return 1;
            }
            if (priv_exists && remove(priv_path) != 0) {
                fprintf(stderr, "Error: Failed to delete '%s': %s\n", priv_path, strerror(errno));
                return 1;
            }
        }
    }

    printf("Generating Master Key Pair for '%s'...\n", name);

    hsc_master_key_pair* kp = hsc_generate_master_key_pair();
    if (!kp) {
        fprintf(stderr, "Fatal Error: Key pair generation failed (Internal Error).\n");
        return 1;
    }

    // Call Kernel API to save files.
    // Note: Kernel now uses O_EXCL (CREATE_NEW), so if we failed to clean up above
    // or if a race condition occurs, this will still fail safely.
    int ret = hsc_save_master_key_pair(kp, pub_path, priv_path);
    
    hsc_free_master_key_pair(&kp);

    if (ret == HSC_OK) {
        printf("Success! Keys generated:\n");
        printf("  > Public:  %s\n", pub_path);
        printf("  > Private: %s (KEEP SECRET)\n", priv_path);
        return 0;
    } else if (ret == HSC_ERROR_FILE_IO) {
        fprintf(stderr, "Error: Failed to write key files (File I/O Error).\n");
        fprintf(stderr, "Hint: Check permissions or if file was created by another process.\n");
        return 1;
    } else {
        fprintf(stderr, "Error: Failed to save keys (Error Code: %d)\n", ret);
        return 1;
    }
}

// --- Main Entry Point & Dispatcher ---

// Simple logging callback for the CLI
void cli_logger(int level, const char* message) {
    if (level >= 1) { // Warn or Error
        fprintf(stderr, "[LibLog] %s\n", message);
    }
}

int main(int argc, char** argv) {
    // Initialize Core Library
    if (hsc_init(NULL, NULL) != HSC_OK) {
        fprintf(stderr, "Fatal Error: Oracipher Core initialization failed.\n");
        return 1;
    }
    hsc_set_log_callback(cli_logger);

    if (argc < 2) {
        print_usage(argv[0]);
        hsc_cleanup();
        return 1;
    }

    const char* command = argv[1];
    int ret = 0;

    // Command Dispatcher
    if (strcmp(command, "gen-keypair") == 0) {
        // Pass arguments starting from argv[1] (command name) to handler
        ret = cmd_gen_keypair(argc - 1, argv + 1);
    } else if (strcmp(command, "help") == 0 || strcmp(command, "--help") == 0) {
        print_usage(argv[0]);
        ret = 0;
    } else {
        fprintf(stderr, "Error: Unknown command '%s'\n\n", command);
        print_usage(argv[0]);
        ret = 1;
    }

    hsc_cleanup();
    return ret;
}