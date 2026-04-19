cmake_minimum_required(VERSION 3.16)
project(Obelisk LANGUAGES CXX)

# ------------------ C++ standard ------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ------------------ Sources ------------------
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
file(GLOB_RECURSE SOURCES ${SRC_DIR}/*.cpp ${SRC_DIR}/*.h)

add_executable(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${SRC_DIR})


find_package(Threads REQUIRED) 
find_package(spdlog CONFIG REQUIRED)
find_package(asio CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(httplib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)

target_compile_definitions(${PROJECT_NAME} PRIVATE 
    CPPHTTPLIB_OPENSSL_SUPPORT
)

target_link_libraries(${PROJECT_NAME}
    PRIVATE
        spdlog::spdlog
        asio::asio
        OpenSSL::SSL
        OpenSSL::Crypto
        httplib::httplib
        nlohmann_json::nlohmann_json
        Threads::Threads 

)

# ------------------ Windows specific ------------------
if(WIN32 AND MSVC)
    target_compile_definitions(${PROJECT_NAME}
        PRIVATE
            _WIN32_WINNT=0x0A00
            WINVER=0x0A00
            OPENSSL_SUPPRESS_DEPRECATED
    )
endif()
message(STATUS "Test sources:")
message(STATUS "tests/test_main.cpp")
message(STATUS "src/manager/Data.cpp")
# ------------------ Tests ------------------
enable_testing()

add_executable(Obelisk_tests
    tests/test_main.cpp
    src/logger/logger.cpp
    src/manager/Data.cpp
    src/manager/Server_manager.cpp
    src/manager/Setup_Wizard.cpp
    src/server/Server_class.cpp
    src/tls/tls_session.cpp
    src/web/web.cpp
)

target_include_directories(Obelisk_tests PRIVATE ${SRC_DIR})

target_link_libraries(Obelisk_tests
    PRIVATE
        GTest::gtest_main
        spdlog::spdlog
        asio::asio
        OpenSSL::SSL
        OpenSSL::Crypto
        nlohmann_json::nlohmann_json
        Threads::Threads
)

include(GoogleTest)
gtest_discover_tests(Obelisk_tests)