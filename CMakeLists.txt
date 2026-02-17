cmake_minimum_required(VERSION 3.16)

# ------------------ Project definition ------------------
project(ObeliskServer LANGUAGES CXX)

# ------------------ C++ standard ------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ------------------ Directory paths ------------------
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/Lib)

# ------------------ External dependencies: spdlog ------------------
include(FetchContent)

FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG v1.13.0
)

FetchContent_MakeAvailable(spdlog)

# ------------------ Collect all source and header files automatically ------------------
file(GLOB_RECURSE SOURCES
    ${SRC_DIR}/*.cpp
    ${SRC_DIR}/*.h    # for IDE visibility
)

# ------------------ Define target ------------------
set(TARGET_NAME ${PROJECT_NAME})
add_executable(${TARGET_NAME} ${SOURCES})

# ------------------ Include directories ------------------
# Add root src directory to include path
target_include_directories(${TARGET_NAME} PRIVATE ${SRC_DIR})

# ------------------ Platform-specific libraries ------------------
if(WIN32)
    # ------------------ Require Windows 10 or higher ------------------
    if(MSVC)
        # Define Windows 10 minimum for MSVC
        target_compile_definitions(${TARGET_NAME} PRIVATE _WIN32_WINNT=0x0A00 WINVER=0x0A00)
        # Suppress OpenSSL 3.0 deprecation warnings
        target_compile_definitions(${TARGET_NAME} PRIVATE OPENSSL_SUPPRESS_DEPRECATED)
    endif()

    # Windows includes
    target_include_directories(${TARGET_NAME} PRIVATE
        ${LIB_DIR}/asio-1.36.0/include
        ${LIB_DIR}/openssl/include
    )
    # Windows linking
    target_link_libraries(${TARGET_NAME} PRIVATE
        ${LIB_DIR}/openssl/lib/libssl.lib
        ${LIB_DIR}/openssl/lib/libcrypto.lib
    )
else()
    # Linux / macOS includes
    find_path(ASIO_INCLUDE_DIR asio.hpp)
    if(NOT ASIO_INCLUDE_DIR)
        set(ASIO_INCLUDE_DIR ${LIB_DIR}/asio-1.36.0/include)
    endif()
    target_include_directories(${TARGET_NAME} PRIVATE ${ASIO_INCLUDE_DIR})

    # OpenSSL
    find_package(OpenSSL REQUIRED)
    target_include_directories(${TARGET_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${TARGET_NAME} PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        pthread
    )
endif()

# ------------------ Link external libraries ------------------
target_link_libraries(${TARGET_NAME} PRIVATE spdlog::spdlog)

# ------------------
