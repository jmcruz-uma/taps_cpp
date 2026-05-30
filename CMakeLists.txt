# Versión mínima requerida de CMake
cmake_minimum_required(VERSION 3.10)

# Nombre del proyecto y versión
project(TAPS_Project VERSION 1.0.0 LANGUAGES CXX)

# Estándar de C++
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Configuraciones de compilación con flag ASIO_STANDALONE
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Wpedantic -DASIO_STANDALONE")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG -DASIO_STANDALONE")

# =============================================================================
# ASIO standalone configuration
# =============================================================================
# Option 1 (recommended): FetchContent — downloads Asio automatically
include(FetchContent)
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG        asio-1-32-0
    SOURCE_SUBDIR  asio
)
FetchContent_MakeAvailable(asio)

# Option 2: Set ASIO_INCLUDE_DIR manually if you have Asio installed locally
# Uncomment and set the path:
# set(ASIO_INCLUDE_DIR "/usr/local/include" CACHE PATH "Path to ASIO standalone headers")
# If neither FetchContent nor ASIO_INCLUDE_DIR works, the FetchContent above
# will download and configure Asio automatically.

# Asio header-only: we only need the include path
if(NOT asio_SOURCE_DIR)
    # Fallback: use ASIO_INCLUDE_DIR if set
    if(NOT ASIO_INCLUDE_DIR OR NOT EXISTS "${ASIO_INCLUDE_DIR}/asio.hpp")
        message(FATAL_ERROR 
            "Asio not found. Either:\n"
            "  1. Let FetchContent download it (default)\n"
            "  2. Set -DASIO_INCLUDE_DIR=/path/to/asio/include\n"
            "  3. Install Asio: git clone https://github.com/chriskohlhoff/asio.git")
    endif()
    include_directories(${ASIO_INCLUDE_DIR})
else()
    # FetchContent: asio headers are in asio/include (standalone layout)
    include_directories(${asio_SOURCE_DIR}/asio/include)
endif()

# Project headers
include_directories(${CMAKE_SOURCE_DIR}/include)

# Agregar subdirectorios
add_subdirectory(src)        # Biblioteca TAPS
add_subdirectory(examples)   # Ejemplos

# Opcional: Instalar headers públicos
install(DIRECTORY include/taps 
        DESTINATION include 
        FILES_MATCHING PATTERN "*.h")