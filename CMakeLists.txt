cmake_minimum_required(VERSION 3.19)
project(AssetDiscovery C)

set (CMAKRE_C_STANDARD 99)
include_directories(include)
add_executable(asset-discovery
    src/main.c
    src/asset-discovery.c
)
if(WIN32)
    target_compile_definitions(asset-discovery PRIVATE _WIN32)
    target_link_libraries(asset-discovery PRIVATE ws2_32)
endif()