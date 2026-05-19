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
# Ruta específica del usuario ASIO
set(ASIO_INCLUDE_DIR "/home/alumno/libs/asio/asio/include" CACHE PATH "Path to ASIO standalone headers")

# Opción alternativa: Variable de entorno (más flexible para otros usuarios)
# set(ASIO_INCLUDE_DIR "$ENV{ASIO_ROOT}/include" CACHE PATH "Path to ASIO standalone headers")

# Verificar que ASIO existe
if(NOT EXISTS "${ASIO_INCLUDE_DIR}/asio.hpp")
    message(FATAL_ERROR "ASIO not found at ${ASIO_INCLUDE_DIR}. Please set ASIO_INCLUDE_DIR to the correct path.")
endif()

message(STATUS "Using ASIO from: ${ASIO_INCLUDE_DIR}")

# Directorio donde CMake buscará los headers (incluir ASIO)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${ASIO_INCLUDE_DIR})

# Agregar subdirectorios
add_subdirectory(src)        # Biblioteca TAPS
add_subdirectory(examples)   # Ejemplos

# Opcional: Instalar headers públicos
install(DIRECTORY include/taps 
        DESTINATION include 
        FILES_MATCHING PATTERN "*.h")