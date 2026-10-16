cmake_minimum_required(VERSION 3.10)
project(UIT_NT219_AES_Lab VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Export all symbols on Windows when building shared library (.dll + import .lib)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

# Library source files: AES core + 5 NIST SP 800-38 standards (A, C, D, E, F; Standard B excluded) + C API
set(AES_LIB_SOURCES
    AES.cpp
    sp800_38a.cpp
    sp800_38c.cpp
    sp800_38d.cpp
    sp800_38e.cpp
    sp800_38f.cpp
    c_api.cpp
)

# 1. Static Library: produces libaes_crypto.a (Linux/macOS/MinGW) or aes_crypto_static.lib (MSVC)
add_library(aes_crypto_static STATIC ${AES_LIB_SOURCES})
set_target_properties(aes_crypto_static PROPERTIES OUTPUT_NAME "aes_crypto")
target_include_directories(aes_crypto_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# 2. Shared / Dynamic Library: produces libaes_crypto.so (Linux), libaes_crypto.dylib (macOS), or aes_crypto.dll (Windows)
add_library(aes_crypto_shared SHARED ${AES_LIB_SOURCES})
set_target_properties(aes_crypto_shared PROPERTIES OUTPUT_NAME "aes_crypto")
target_compile_definitions(aes_crypto_shared PRIVATE AES_CRYPTO_EXPORTS)
target_include_directories(aes_crypto_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# 3. C++ Test & CLI Executable (main / main.exe) linked against static library
add_executable(main main.cpp)
target_link_libraries(main PRIVATE aes_crypto_static)

# 4. C Language Import Demo Executable (test_c / test_c.exe) linked against static library
add_executable(test_c test_c.c)
target_link_libraries(test_c PRIVATE aes_crypto_static)
if(UNIX)
    target_link_libraries(test_c PRIVATE stdc++)
endif()
