# Recopilar todos los archivos fuente de TAPS
file(GLOB_RECURSE TAPS_SOURCES
     "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/*.cc")

# Recopilar todos los headers privados (si los hay en src/)
file(GLOB_RECURSE TAPS_PRIVATE_HEADERS
     "${CMAKE_CURRENT_SOURCE_DIR}/*.h")

# The OpenSSL-backed TLS sources (security/tls_*.cpp) only build with TAPS_WITH_TLS;
# security_provider.h is an OpenSSL-free interface and always compiles.
if(NOT TAPS_WITH_TLS)
    list(FILTER TAPS_SOURCES EXCLUDE REGEX "/security/tls_")
endif()

# Crear la biblioteca estática
add_library(taps_static STATIC ${TAPS_SOURCES})

# Alias más limpio para usar en otros targets
add_library(TAPS::static ALIAS taps_static)

# Configurar propiedades de la biblioteca
set_target_properties(taps_static PROPERTIES
    OUTPUT_NAME "taps"           # El archivo se llamará libtaps.a
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "${PROJECT_SOURCE_DIR}/include/taps/taps_api.h"
)

# Directorios de include para esta biblioteca
target_include_directories(taps_static 
    PUBLIC 
        ${PROJECT_SOURCE_DIR}/include
        ${ASIO_INCLUDE_DIR}        # ASIO disponible para usuarios de la biblioteca
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}
)

# Definir ASIO_STANDALONE para la biblioteca
target_compile_definitions(taps_static PUBLIC ASIO_STANDALONE)

# TLS support: OpenSSL + the TAPS_WITH_TLS switch the sources compile against.
if(TAPS_WITH_TLS)
    find_package(OpenSSL REQUIRED)
    target_link_libraries(taps_static PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(taps_static PRIVATE TAPS_WITH_TLS)
    message(STATUS "TAPS: TLS support ON (OpenSSL ${OPENSSL_VERSION})")
else()
    message(STATUS "TAPS: TLS support OFF")
endif()

# Enlaces con librerías del sistema si son necesarias
# ASIO standalone necesita estas librerías del sistema
if(UNIX AND NOT APPLE)
    target_link_libraries(taps_static PRIVATE pthread)
elseif(WIN32)
    target_link_libraries(taps_static PRIVATE ws2_32 wsock32)
endif()

# Instalar la biblioteca
install(TARGETS taps_static
        EXPORT TAPSTargets
        ARCHIVE DESTINATION lib
        PUBLIC_HEADER DESTINATION include/taps)