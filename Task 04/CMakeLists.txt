cmake_minimum_required(VERSION 3.14)
project(UIT_NT219_AES_Modes VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

# Automatically configure C compiler alongside CXX compiler (e.g. D:/msys64/mingw64/bin/g++.exe -> gcc.exe)
if(NOT CMAKE_C_COMPILER AND CMAKE_CXX_COMPILER)
    get_filename_component(_cxx_compiler_name "${CMAKE_CXX_COMPILER}" NAME)
    if(_cxx_compiler_name STREQUAL "g++" OR _cxx_compiler_name STREQUAL "g++.exe")
        get_filename_component(_cxx_compiler_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
        if(_cxx_compiler_name STREQUAL "g++.exe")
            set(_derived_c_compiler "${_cxx_compiler_dir}/gcc.exe")
        else()
            set(_derived_c_compiler "${_cxx_compiler_dir}/gcc")
        endif()
        if(EXISTS "${_derived_c_compiler}")
            set(CMAKE_C_COMPILER "${_derived_c_compiler}" CACHE FILEPATH "C compiler" FORCE)
        endif()
    endif()
endif()
include(CheckLanguage)
check_language(C)
if(CMAKE_C_COMPILER)
    enable_language(C)
    set(CMAKE_C_STANDARD 11)
    set(CMAKE_C_STANDARD_REQUIRED ON)
endif()

# Lecturer Reference Options:
#   -DAES_BUILD_EXECUTABLE=ON|OFF
#   -DAES_LIBRARY_TYPE=STATIC|SHARED|BOTH
#   -DAES_BUILD_TESTS=ON|OFF
option(AES_BUILD_EXECUTABLE "Build CLI and verification executables" ON)
option(AES_BUILD_TESTS "Build and register CTest verification suites" ON)
set(AES_LIBRARY_TYPE "BOTH" CACHE STRING "Library type to build: STATIC, SHARED, or BOTH")
set_property(CACHE AES_LIBRARY_TYPE PROPERTY STRINGS STATIC SHARED BOTH)

string(TOUPPER "${AES_LIBRARY_TYPE}" AES_LIBRARY_TYPE_UPPER)
if(NOT AES_LIBRARY_TYPE_UPPER MATCHES "^(STATIC|SHARED|BOTH)$")
    message(FATAL_ERROR "Invalid AES_LIBRARY_TYPE='${AES_LIBRARY_TYPE}'. Must be STATIC, SHARED, or BOTH.")
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings OPTIONAL)

set(AES_LIB_SOURCES
    src/AES.cpp
    src/sp800_38a.cpp
    src/sp800_38c.cpp
    src/sp800_38d.cpp
    src/sp800_38e.cpp
    src/sp800_38f.cpp
    src/c_api.cpp
)

set(AES_PRIMARY_LIB_TARGET "")

# 1. Static Library (.a on Linux/MinGW, .lib on MSVC)
if(AES_LIBRARY_TYPE_UPPER STREQUAL "STATIC" OR AES_LIBRARY_TYPE_UPPER STREQUAL "BOTH")
    add_library(aes_crypto_static STATIC ${AES_LIB_SOURCES})
    set_target_properties(aes_crypto_static PROPERTIES OUTPUT_NAME "aes_crypto")
    target_include_directories(aes_crypto_static PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
    if(COMMAND uit_set_project_warnings)
        uit_set_project_warnings(aes_crypto_static)
    endif()
    set(AES_PRIMARY_LIB_TARGET aes_crypto_static)
endif()

# 2. Shared Library (.so on Linux, .dll + .dll.a on MinGW, .dll + .lib on MSVC)
if(AES_LIBRARY_TYPE_UPPER STREQUAL "SHARED" OR AES_LIBRARY_TYPE_UPPER STREQUAL "BOTH")
    add_library(aes_crypto_shared SHARED ${AES_LIB_SOURCES})
    set_target_properties(aes_crypto_shared PROPERTIES OUTPUT_NAME "aes_crypto")
    target_compile_definitions(aes_crypto_shared PRIVATE AES_CRYPTO_EXPORTS)
    target_include_directories(aes_crypto_shared PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
    if(COMMAND uit_set_project_warnings)
        uit_set_project_warnings(aes_crypto_shared)
    endif()
    if(NOT AES_PRIMARY_LIB_TARGET)
        set(AES_PRIMARY_LIB_TARGET aes_crypto_shared)
    endif()
endif()

# 3. Executables (Controlled by -DAES_BUILD_EXECUTABLE=ON)
if(AES_BUILD_EXECUTABLE)
    add_executable(main src/main.cpp)
    target_link_libraries(main PRIVATE ${AES_PRIMARY_LIB_TARGET})
    if(COMMAND uit_set_project_warnings)
        uit_set_project_warnings(main)
    endif()

    add_executable(test_sp800_38a_38c tests/test_sp800_38a_38c.cpp)
    target_link_libraries(test_sp800_38a_38c PRIVATE ${AES_PRIMARY_LIB_TARGET})
    if(COMMAND uit_set_project_warnings)
        uit_set_project_warnings(test_sp800_38a_38c)
    endif()

    # Task 3: OpenSSL (libcrypto EVP) Cross-Check & Benchmark Executable
    find_package(OpenSSL QUIET)
    add_executable(test_openssl_crosscheck tests/test_openssl_crosscheck.cpp)
    target_link_libraries(test_openssl_crosscheck PRIVATE ${AES_PRIMARY_LIB_TARGET})
    if(OpenSSL_FOUND)
        target_compile_definitions(test_openssl_crosscheck PRIVATE HAVE_OPENSSL=1)
        target_link_libraries(test_openssl_crosscheck PRIVATE OpenSSL::Crypto)
    endif()
    if(COMMAND uit_set_project_warnings)
        uit_set_project_warnings(test_openssl_crosscheck)
    endif()

    if(CMAKE_C_COMPILER)
        add_executable(test_c tests/test_c.c)
        target_link_libraries(test_c PRIVATE ${AES_PRIMARY_LIB_TARGET})
        if(UNIX OR MINGW)
            target_link_libraries(test_c PRIVATE stdc++ m)
        endif()
    endif()
endif()

# 4. CTest Suite (for `ctest --test-dir build-gcc-attn --output-on-failure`)
if(AES_BUILD_TESTS AND AES_BUILD_EXECUTABLE)
    enable_testing()
    add_test(NAME AES_FIPS197_KAT COMMAND main)
    add_test(NAME NIST_SP800_38A_38C_Suite COMMAND test_sp800_38a_38c)
    add_test(NAME OpenSSL_CrossCheck_Suite COMMAND test_openssl_crosscheck)
    if(TARGET test_c)
        add_test(NAME C_API_Import_Test COMMAND test_c)
    endif()
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND AND (AES_LIBRARY_TYPE_UPPER STREQUAL "SHARED" OR AES_LIBRARY_TYPE_UPPER STREQUAL "BOTH"))
        add_test(
            NAME Python_ctypes_SharedLib_Test
            COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_import.py"
        )
    endif()
endif()
