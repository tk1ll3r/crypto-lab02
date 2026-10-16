# cmake/Toolchain-GCC.cmake
# Explicit GCC/G++ Toolchain file for building in modes/build-gcc/
# Usage:
#   cmake -S . -B build-gcc -DCMAKE_TOOLCHAIN_FILE=cmake/Toolchain-GCC.cmake
#   cmake --build build-gcc

set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
