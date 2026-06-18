cmake_minimum_required(VERSION 3.20)
project(diarna VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "Diarna requires Windows")
endif()

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_options(/O2 /MT /GS- /Gy /Gw /bigobj)
    add_link_options(/LTCG /OPT:REF /OPT:ICF)
    set(DIARNA_COMPILER_FLAGS "")
elseif(MINGW)
    add_compile_options(-O2 -masm=intel -fno-asynchronous-unwind-tables -fno-ident
        -fno-stack-protector -fvisibility=hidden -ffunction-sections -fdata-sections)
    add_link_options(-Wl,--gc-sections -Wl,--strip-all -static-libgcc -static-libstdc++)
    set(DIARNA_COMPILER_FLAGS -static)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")
endif()

file(GLOB_RECURSE DIARNA_SOURCES src/*.cpp)

add_library(diarna_core STATIC ${DIARNA_SOURCES})

target_include_directories(diarna_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../daemon/include
)

target_compile_definitions(diarna_core PRIVATE
    DIARNA_STATIC
    OBF_UNSUPPORTED
    CONST_ENCRYPTION=1
    CONST_ENCRYPT_MODE=NORMAL
    INDIRECT_BRANCHING=1
    CFLOW_CONST_DECRYPTION=1
    CFLOW_BRANCHING=0
    FAKE_SIGNATURES=1
)

target_link_libraries(diarna_core PUBLIC
    ws2_32 mincore winhttp bcrypt crypt32 advapi32
    ole32 oleaut32 user32 gdi32 shell32 mfuuid
    taskschd wbemuuid wevtapi iphlpapi
    wlanapi powrprof psapi setupapi
)

add_executable(diarna_example example/main.cpp)
target_link_libraries(diarna_example PRIVATE diarna_core)

set_target_properties(diarna_core PROPERTIES OUTPUT_NAME "diarna")
