# Makefile for Scythe C++ Implant
# Supports both clang++ and g++

# Compiler settings
CXX := clang++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -pthread
DEBUGFLAGS := -std=c++17 -Wall -Wextra -g -DDEBUG -pthread

# Directories
SRCDIR := src
OBJDIR := obj
BINDIR := bin
TARGET := $(BINDIR)/implant

# Source files
SOURCES := $(wildcard $(SRCDIR)/*.cpp)
OBJECTS := $(SOURCES:$(SRCDIR)/%.cpp=$(OBJDIR)/%.o)

# Boost settings
BOOST_LIBS := -lboost_system -lboost_filesystem -lboost_thread
BOOST_INCLUDE := -I/usr/include/boost -I/usr/local/include/boost -I/opt/homebrew/include/boost

# CPR HTTP library settings
CPR_LIBS := -lcpr -lcurl

# System specific settings
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    BOOST_LIB_DIR := -L/usr/lib/x86_64-linux-gnu -L/usr/local/lib
endif
ifeq ($(UNAME_S),Darwin)
    BOOST_LIB_DIR := -L/opt/homebrew/lib -L/usr/local/lib
    CXXFLAGS += -mmacosx-version-min=10.15
endif

# Windows/MinGW settings
ifneq (,$(findstring MINGW,$(UNAME_S)))
    BOOST_LIB_DIR := -L/mingw64/lib
    TARGET := $(BINDIR)/implant.exe
endif

# Linker flags
LDFLAGS := $(BOOST_LIB_DIR) $(BOOST_LIBS) $(CPR_LIBS)

# Default target
all: directories $(TARGET)

# Create directories
directories:
	@mkdir -p $(OBJDIR) $(BINDIR)

# Build target
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

# Compile source files
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(BOOST_INCLUDE) -c $< -o $@

# Debug build
debug: CXXFLAGS = $(DEBUGFLAGS)
debug: directories $(TARGET)

# Clean build files
clean:
	rm -rf $(OBJDIR) $(BINDIR)
	@echo "Cleaned build files"

# Install boost dependencies (Linux/macOS)
install-deps:
ifeq ($(UNAME_S),Linux)
	sudo apt-get update && sudo apt-get install libboost-all-dev libcpr-dev libcurl4-openssl-dev
endif
ifeq ($(UNAME_S),Darwin)
	brew install boost cpr
endif

# Test compilation
test:
	@echo "Testing compilation with current settings..."
	@echo "Compiler: $(CXX)"
	@echo "Flags: $(CXXFLAGS)"
	@echo "Boost include: $(BOOST_INCLUDE)"
	@echo "Boost libs: $(BOOST_LIB_DIR) $(BOOST_LIBS)"
	$(CXX) --version

# Alternative build with g++
gcc: CXX = g++
gcc: all

# Static build (for deployment)
static: LDFLAGS += -static-libgcc -static-libstdc++
static: all

# Release build (optimized)
release: CXXFLAGS = -std=c++17 -O3 -DNDEBUG -pthread
release: directories $(TARGET)

.PHONY: all directories clean debug install-deps test gcc static release
