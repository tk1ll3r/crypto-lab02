# cmake/CompilerWarnings.cmake
# Cross-platform compiler warning and optimization configuration for UIT NT219 AES Lab.

function(uit_set_project_warnings target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE /W4 /EHsc)
    else()
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -Wpedantic -O2)
    endif()
endfunction()
