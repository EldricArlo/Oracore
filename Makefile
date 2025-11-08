#
# Makefile for the High-Security Hybrid Encryption System
# [REVISED by the Code Review Committee]
#

# --- Compiler and Flags ---
CC = gcc
# [FIX 1/4] Added -MMD and -MP to CFLAGS.
# -MMD: Generate a dependency file (.d) for each source file.
# -MP:  Create phony targets for each dependency, preventing errors if a header is deleted.
CFLAGS = -g -I./src -Wall -Wextra -std=c11 -MMD -MP
TEST_CFLAGS = $(CFLAGS)
# Linker flags for all targets
LDFLAGS = -lsodium -lssl -lcrypto
# Linker flags for tests
TEST_LDFLAGS = $(LDFLAGS)


# --- Source Files & Object Files ---
# Library sources and their corresponding object files
LIB_SRCS = $(wildcard src/common/*.c) $(wildcard src/core_crypto/*.c) $(wildcard src/pki/*.c)
LIB_OBJS = $(LIB_SRCS:.c=.o)

# Main application source and its object file
APP_MAIN_SRC = src/main.c
APP_MAIN_OBJ = $(APP_MAIN_SRC:.c=.o)
APP_EXECUTABLE = high_security_app

# Test suite sources and their object files
TEST_SRCS = $(wildcard tests/*.c)
TEST_OBJS = $(TEST_SRCS:.c=.o)
TEST_EXECUTABLES = $(patsubst tests/%.c, %, $(TEST_SRCS))

# [NEW] A comprehensive list of ALL object files and dependency files for easier management.
ALL_OBJS = $(LIB_OBJS) $(APP_MAIN_OBJ) $(TEST_OBJS)
DEPS = $(ALL_OBJS:.o=.d)


# --- Build Rules ---

# Default target when you just type 'make'
all: $(APP_EXECUTABLE)

# [FIX 2/4] The linking rule is now decoupled from compilation.
# It depends only on object files.
$(APP_EXECUTABLE): $(LIB_OBJS) $(APP_MAIN_OBJ)
	@echo "Linking main application: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# A special "meta-target" for all tests
build_tests: $(TEST_EXECUTABLES)

# A generic pattern rule to build any test executable from its corresponding object file.
# The prerequisites are all library objects and the specific test's object file (e.g., tests/test_core_crypto.o).
$(TEST_EXECUTABLES): % : $(LIB_OBJS) tests/%.o
	@echo "Linking test executable: $@"
	$(CC) $(TEST_CFLAGS) -o $@ $^ $(TEST_LDFLAGS)

# This single generic rule now compiles ALL .c files into .o files,
# whether they are in src/ or tests/. The magic of Make handles the paths.
# During compilation, the -MMD flag also creates the corresponding .d dependency file.
%.o: %.c
	@echo "Compiling $<"
	$(CC) $(CFLAGS) -c $< -o $@


# --- Commands ---

# The main command to run all tests.
test: build_tests
	@echo "\n--- Running all test suites ---"
	@for test_exe in $(TEST_EXECUTABLES); do \
		echo "[RUNNING] ./$$test_exe"; \
		./$$test_exe; \
	done
	@echo "--- All test suites finished ---\n"


# [FIX 3/4] The clean rule is updated to remove all generated object files (.o)
# and dependency files (.d), in addition to the executables.
clean:
	@echo "Cleaning up..."
	rm -f $(ALL_OBJS) $(DEPS) $(APP_EXECUTABLE) $(TEST_EXECUTABLES)

# Declare targets that are not actual files
.PHONY: all test build_tests clean


# --- Dependency Inclusion ---
# [FIX 4/4] This is the core of the fix. It tells 'make' to include all the
# generated .d files. These files contain the rules that link header files
# to their corresponding object files. The '-' prefix prevents errors if
# the .d files don't exist yet (e.g., during the first run or after a 'clean').
-include $(DEPS)