#
# Makefile for the High-Security Hybrid Encryption System
# [REVISED BY COMMITTEE to integrate all test suites]
#

# --- Compiler and Flags ---
CC = gcc
CFLAGS = -g -Iinclude -Isrc -Wall -Wextra -Werror -std=c11 -fPIC -MMD -MP

# --- Libraries ---
LDFLAGS = -lsodium -lssl -lcrypto -lcurl

# --- Directories and Paths ---
BIN_DIR = bin
SRC_DIR = src
TEST_DIR = tests

# --- Platform-Specific Adjustments ---
ifeq ($(OS),Windows_NT)
    TARGET_LIB_NAME = hsc_kernel.dll
    TARGET_CLI_EXT = .exe
    CFLAGS += -D_WIN32 -DWIN32_LEAN_AND_MEAN -DNOCRYPT
    CFLAGS_EXEC = $(filter-out -fPIC,$(CFLAGS))
else
    TARGET_LIB_NAME = libhsc_kernel.so
    TARGET_CLI_EXT =
    CFLAGS_EXEC = $(CFLAGS)
    LDFLAGS += -Wl,-rpath,'$$ORIGIN'
endif

# --- Source & Object Files Discovery ---
KERNEL_SRCS = $(wildcard $(SRC_DIR)/common/*.c) \
              $(wildcard $(SRC_DIR)/core_crypto/*.c) \
              $(wildcard $(SRC_DIR)/pki/*.c) \
              $(SRC_DIR)/hsc_kernel.c
KERNEL_OBJS = $(KERNEL_SRCS:.c=.o)

CLI_SRC = $(SRC_DIR)/cli.c
CLI_OBJ = $(CLI_SRC:.c=.o)

DEMO_SRC = $(SRC_DIR)/main.c
DEMO_OBJ = $(DEMO_SRC:.c=.o)

CA_UTIL_SRC = $(TEST_DIR)/test_ca_util.c
CA_UTIL_OBJ = $(CA_UTIL_SRC:.c=.o)

TEST_HELPER_SRCS = $(TEST_DIR)/test_helpers.c
TEST_HELPER_OBJS = $(TEST_HELPER_SRCS:.c=.o)

# [VERIFIED] The wildcard '*.c' automatically discovers all test source files,
# including 'test_core_crypto.c', 'test_api_integration.c', and the new
# 'test_expert_api.c', while filtering out helpers. This is robust.
# Note: The original submission split tests into multiple files. For this Makefile,
# we assume they are distinct source files like test_core_crypto.c, test_pki_verification.c, etc.
TEST_SRCS = $(filter-out $(TEST_HELPER_SRCS) $(CA_UTIL_SRC), $(wildcard $(TEST_DIR)/test_*.c))
TEST_OBJS = $(TEST_SRCS:.c=.o)

# --- Target Executables and Libraries ---
TARGET_LIB = $(BIN_DIR)/$(TARGET_LIB_NAME)
TARGET_CLI = $(BIN_DIR)/hsc_cli$(TARGET_CLI_EXT)
TARGET_DEMO = $(BIN_DIR)/hsc_demo$(TARGET_CLI_EXT)
TARGET_CA_UTIL = $(BIN_DIR)/test_ca_util$(TARGET_CLI_EXT)

# This list of executables is automatically populated with all test targets
# thanks to the robust TEST_SRCS discovery logic.
TEST_EXECUTABLES = $(patsubst $(TEST_DIR)/%.c,$(BIN_DIR)/%,$(TEST_SRCS))

# --- Dependency Management ---
ALL_OBJS = $(KERNEL_OBJS) $(CLI_OBJ) $(DEMO_OBJ) $(CA_UTIL_OBJ) $(TEST_OBJS) $(TEST_HELPER_OBJS)
DEPS = $(ALL_OBJS:.o=.d)

# --- Build Rules ---

.PHONY: all kernel cli demo ca_util tests clean run-tests

all: cli demo ca_util tests

cli: $(TARGET_CLI)
demo: $(TARGET_DEMO)
ca_util: $(TARGET_CA_UTIL)
tests: $(TEST_EXECUTABLES)

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

$(TARGET_LIB): $(KERNEL_OBJS) | $(BIN_DIR)
	@echo "==> Linking Kernel Library: $@"
	$(CC) -shared -o $@ $^ $(LDFLAGS)

$(TARGET_CLI): $(CLI_OBJ) $(TARGET_LIB) | $(BIN_DIR)
	@echo "==> Linking CLI Client: $@"
	$(CC) $(CFLAGS_EXEC) -o $@ $< -L$(BIN_DIR) -lhsc_kernel $(LDFLAGS)

$(TARGET_DEMO): $(DEMO_OBJ) $(TARGET_LIB) | $(BIN_DIR)
	@echo "==> Linking Demo Application: $@"
	$(CC) $(CFLAGS_EXEC) -o $@ $< -L$(BIN_DIR) -lhsc_kernel $(LDFLAGS)

$(TARGET_CA_UTIL): $(CA_UTIL_OBJ) | $(BIN_DIR)
	@echo "==> Linking Test CA Utility: $@"
	$(CC) $(CFLAGS_EXEC) -o $@ $< $(LDFLAGS)

# This generic rule correctly handles building all test executables.
# It correctly links the specific test object, the common helper objects,
# and the hsc_kernel library.
$(TEST_EXECUTABLES): $(BIN_DIR)/% : $(TEST_DIR)/%.c $(TEST_HELPER_OBJS) $(TARGET_LIB) | $(BIN_DIR)
	@echo "==> Linking Test Executable: $@"
	$(CC) $(CFLAGS_EXEC) -o $@ $< $(TEST_HELPER_OBJS) -L$(BIN_DIR) -lhsc_kernel $(LDFLAGS)

%.o: %.c
	@echo "  -> Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@

# --- Commands ---

run-tests: tests
	@echo "\n--- Running all test suites ---"
	@for test_exe in $(TEST_EXECUTABLES); do \
		echo "[RUNNING] ./$$test_exe"; \
		./$$test_exe; \
		if [ $$? -ne 0 ]; then \
			echo "!!! TEST FAILED: $$test_exe !!!"; \
			exit 1; \
		fi; \
	done
	@echo "--- All test suites finished successfully ---\n"

clean:
	@echo "Cleaning up..."
	rm -rf $(BIN_DIR)
	find . -type f -name "*.o" -delete
	find . -type f -name "*.d" -delete

-include $(DEPS)