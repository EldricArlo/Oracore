#
# Makefile for the High-Security Hybrid Encryption System
# [最终修订版 by the Code Review Committee]
#

# --- Compiler and Flags ---
CC = gcc
# CFLAGS: -g for debug, -I for include path, Wall/Wextra for warnings, std=c11 for standard
# -MMD -MP for auto dependency generation
# -DWIN32_LEAN_AND_MEAN -DNOCRYPT for Windows compatibility with OpenSSL
CFLAGS = -g -I./src -Wall -Wextra -std=c11 -MMD -MP -DWIN32_LEAN_AND_MEAN -DNOCRYPT

# --- Libraries ---
# Common libraries needed for linking applications and tests
LDFLAGS = -lsodium -lssl -lcrypto -lcurl

# --- Directories and Paths ---
# [委员会改进] 将所有输出统一管理到 bin/ 目录
BIN_DIR = bin
SRC_DIR = src
TEST_DIR = tests

# --- Source & Object Files Discovery ---
# [委员会改进] 自动发现所有模块的源文件
LIB_SRCS = $(wildcard $(SRC_DIR)/common/*.c) $(wildcard $(SRC_DIR)/core_crypto/*.c) $(wildcard $(SRC_DIR)/pki/*.c)
LIB_OBJS = $(LIB_SRCS:.c=.o)

# Main application files
APP_MAIN_SRC = $(SRC_DIR)/main.c
APP_MAIN_OBJ = $(APP_MAIN_SRC:.c=.o)
APP_EXECUTABLE = $(BIN_DIR)/high_security_app

# CLI application files
CLI_MAIN_SRC = $(SRC_DIR)/cli.c
CLI_MAIN_OBJ = $(CLI_MAIN_SRC:.c=.o)
CLI_EXECUTABLE = $(BIN_DIR)/hsc_cli

# [委员会核心改进] 自动发现所有测试文件并生成对应的可执行文件路径
# 这将匹配 tests/test_*.c 和 tests/*_test.c 等所有文件
TEST_SRCS = $(wildcard $(TEST_DIR)/test_*.c) $(wildcard $(TEST_DIR)/*_test.c)
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_EXECUTABLES = $(patsubst %.c,$(BIN_DIR)/%,$(notdir $(TEST_SRCS)))

# List of all object files for dependency tracking
ALL_OBJS = $(LIB_OBJS) $(APP_MAIN_OBJ) $(CLI_MAIN_OBJ) $(TEST_OBJS)
DEPS = $(ALL_OBJS:.o=.d)


# --- Build Rules ---

.PHONY: all test build_tests clean

# [委员会改进] 'all' 目标现在依赖于 bin 目录的创建，并构建所有应用
all: $(BIN_DIR) $(APP_EXECUTABLE) $(CLI_EXECUTABLE)

# Rule to create the bin directory if it doesn't exist
$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

# Linking rule for the main application
$(APP_EXECUTABLE): $(APP_MAIN_OBJ) $(LIB_OBJS) | $(BIN_DIR)
	@echo "Linking main application: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Linking rule for the CLI application
$(CLI_EXECUTABLE): $(CLI_MAIN_OBJ) $(LIB_OBJS) | $(BIN_DIR)
	@echo "Linking CLI application: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Main target to build all test executables
build_tests: $(TEST_EXECUTABLES)

# [委员会核心改进] 静态模式规则，用于链接任何一个测试可执行文件
# 例如: 'bin/test_symmetric_crypto' 依赖于 'tests/test_symmetric_crypto.o' 和所有库对象
$(TEST_EXECUTABLES): $(BIN_DIR)/% : $(TEST_DIR)/%.o $(LIB_OBJS) | $(BIN_DIR)
	@echo "Linking test executable: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Generic rule for compiling any .c file to a .o file
%.o: %.c
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@


# --- Commands ---

# [委员会改进] 'test' 目标现在自动运行所有已构建的测试可执行文件
test: build_tests
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

# [委员会改进] 更彻底的清理规则
clean:
	@echo "Cleaning up..."
	rm -rf $(BIN_DIR)
	find $(SRC_DIR) -name "*.o" -delete
	find $(SRC_DIR) -name "*.d" -delete
	find $(TEST_DIR) -name "*.o" -delete
	find $(TEST_DIR) -name "*.d" -delete

# Include automatically generated dependency files
-include $(DEPS)