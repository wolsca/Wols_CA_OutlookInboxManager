cmake_minimum_required(VERSION 3.15)
project(WolsCA_InboxManager VERSION 1.0.0 LANGUAGES CXX)

# Require C++17 standard for std::filesystem compatibility
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Enforce static linking for the C++ runtime to prevent DLL version conflicts
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Automatically fetch the header-only JSON library
include(FetchContent)
FetchContent_Declare(json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

# Define the executable as a Windows GUI application (WIN32 prevents the black console window)
# Paden zijn aangepast naar de Visual Studio submap structuur
add_executable(${PROJECT_NAME} WIN32
    Wols_CA_OutlookInboxManager/Wols_CA_OutlookInboxManager.cpp
    Wols_CA_OutlookInboxManager/Wols_CA_OutlookInboxManager.hpp
    Wols_CA_OutlookInboxManager/resource.rc
)

# Link the JSON library to the target
target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)