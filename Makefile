#
# Makefile for the High-Security Hybrid Encryption System
# [FIXED & ENHANCED by the Code Review Committee]
#

# --- Compiler and Flags ---
CC = gcc
# [COMMITTEE NOTE] Added a target for the demo application
CFLAGS = -g -Iinclude -Isrc -Wall -Wextra -std=c11 -fPIC -MMD -MP -DWIN32_LEAN_AND_MEAN -DNOCRYPT

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

# [COMMITTEE FIX] Define source and object files for the demo application
DEMO_SRC = $(SRC_DIR)/main.c
DEMO_OBJ = $(DEMO_SRC:.c=.o)

TEST_HELPER_SRCS = $(wildcard $(TEST_DIR)/test_helpers.c)
TEST_HELPER_OBJS = $(TEST_HELPER_SRCS:.c=.o)
TEST_SRCS = $(filter-out $(TEST_HELPER_SRCS), $(wildcard $(TEST_DIR)/test_*.c))
TEST_OBJS = $(TEST_SRCS:.c=.o)

# --- Target Executables and Libraries ---
TARGET_LIB = $(BIN_DIR)/$(TARGET_LIB_NAME)
TARGET_CLI = $(BIN_DIR)/hsc_cli$(TARGET_CLI_EXT)
# [COMMITTEE FIX] Add the demo executable target
TARGET_DEMO = $(BIN_DIR)/hsc_demo$(TARGET_CLI_EXT)
TEST_EXECUTABLES = $(patsubst $(TEST_DIR)/%.c,$(BIN_DIR)/%,$(TEST_SRCS))

# --- Dependency Management ---
ALL_OBJS = $(KERNEL_OBJS) $(CLI_OBJ) $(DEMO_OBJ) $(TEST_OBJS) $(TEST_HELPER_OBJS)
DEPS = $(ALL_OBJS:.o=.d)

# --- Build Rules ---

# [COMMITTEE FIX] Add 'demo' to the .PHONY list and the 'all' target
.PHONY: all kernel cli demo tests clean run-tests

all: cli demo tests

# CLI depends on kernel library (implicitly via TARGET_LIB)
cli: $(TARGET_CLI)

# [COMMITTEE FIX] Add the 'demo' phony target
demo: $(TARGET_DEMO)

# Build all test executables
tests: $(TEST_EXECUTABLES)

# Rule to create the bin directory
$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Linking the shared kernel library into the BIN_DIR
$(TARGET_LIB): $(KERNEL_OBJS) | $(BIN_DIR)
	@echo "==> Linking Kernel Library: $@"
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Linking the CLI application, ensuring it looks for the library in BIN_DIR
$(TARGET_CLI): $(CLI_OBJ) $(TARGET_LIB) | $(BIN_DIR)
	@echo "==> Linking CLI Client: $@"
	# [COMMITTEE NOTE] The cli.c object file now depends on the kernel library for linking.
	$(CC) $(CFLAGS_EXEC) -o $@ $< -L$(BIN_DIR) -lhsc_kernel $(LDFLAGS)

# [COMMITTEE FIX] Add the linking rule for the demo application
$(TARGET_DEMO): $(DEMO_OBJ) $(TARGET_LIB) | $(BIN_DIR)
	@echo "==> Linking Demo Application: $@"
	# [COMMITTEE NOTE] The main.c object file also depends on the kernel library.
	$(CC) $(CFLAGS_EXEC) -o $@ $< -L$(BIN_DIR) -lhsc_kernel $(LDFLAGS)

# Linking all test executables, also looking for the library in BIN_DIR
$(TEST_EXECUTABLES): $(BIN_DIR)/% : $(TEST_DIR)/%.o $(TEST_HELPER_OBJS) $(TARGET_LIB) | $(BIN_DIR)
	@echo "==> Linking Test Executable: $@"
	$(CC) $(CFLAGS_EXEC) -o $@ $^ -L$(BIN_DIR) -lhsc_kernel $(LDFLAGS)

# Generic rule for compiling any .c file to a .o file
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