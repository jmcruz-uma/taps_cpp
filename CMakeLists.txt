# Versión mínima requerida de CMake
cmake_minimum_required(VERSION 3.10)

# Nombre del proyecto y versión
project(TAPS_Project VERSION 1.0.0 LANGUAGES CXX)

# Estándar de C++
set(CMAKE_CXX_STANDARD 23)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++23")
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Configuraciones de compilación con flag ASIO_STANDALONE
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -DASIO_STANDALONE")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -DASIO_STANDALONE")

# CONFIGURACIÓN DE ASIO STANDALONE
# Set ASIO_INCLUDE_DIR yourself to reuse an existing checkout; otherwise (the
# default) standalone ASIO is fetched automatically, so a fresh clone of this
# repo builds with no manual setup on any machine.
set(ASIO_INCLUDE_DIR "" CACHE PATH "Path to ASIO standalone headers (leave empty to fetch automatically)")
option(TAPS_FETCH_ASIO "Fetch standalone ASIO via FetchContent when ASIO_INCLUDE_DIR isn't set" ON)

if(ASIO_INCLUDE_DIR STREQUAL "" OR NOT EXISTS "${ASIO_INCLUDE_DIR}/asio.hpp")
    if(NOT TAPS_FETCH_ASIO)
        message(FATAL_ERROR "ASIO not found at '${ASIO_INCLUDE_DIR}'. Set ASIO_INCLUDE_DIR to an existing checkout, or enable TAPS_FETCH_ASIO.")
    endif()
    include(FetchContent)
    FetchContent_Declare(asio_standalone
        GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
        GIT_TAG asio-1-30-2
        GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(asio_standalone)
    set(ASIO_INCLUDE_DIR "${asio_standalone_SOURCE_DIR}/asio/include" CACHE PATH
        "Path to ASIO standalone headers" FORCE)
endif()

message(STATUS "Using ASIO from: ${ASIO_INCLUDE_DIR}")

# Directorio donde CMake buscará los headers (incluir ASIO)
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${ASIO_INCLUDE_DIR})

# TLS support pulls in OpenSSL. Opt-out (-DTAPS_WITH_TLS=OFF) for consumers that
# don't need it: the library then builds with no OpenSSL dependency and requesting
# TLS through SecurityParameters fails at connection establishment.
option(TAPS_WITH_TLS "Build TLS support (requires OpenSSL)" ON)

# Agregar subdirectorios
add_subdirectory(src)        # Biblioteca TAPS

# Examples: opt-out (-DTAPS_BUILD_EXAMPLES=OFF), e.g. when this project is
# pulled in via FetchContent by a consumer that only wants TAPS::static and
# would otherwise collide with its own tcpserver/tcpclient targets.
option(TAPS_BUILD_EXAMPLES "Build TAPS examples" ON)
if(TAPS_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Tests unitarios: opt-in (-DTAPS_BUILD_TESTS=ON). Off por defecto para que los
# consumidores que hacen `cmake --build` sin filtrar target no los construyan.
option(TAPS_BUILD_TESTS "Build TAPS unit tests" OFF)
if(TAPS_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Opcional: Instalar headers públicos
install(DIRECTORY include/taps 
        DESTINATION include 
        FILES_MATCHING PATTERN "*.h")