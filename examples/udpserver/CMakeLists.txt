# Crear ejecutable
add_executable(udpserver main.cpp)

# Enlazar con la biblioteca TAPS
target_link_libraries(udpserver PRIVATE TAPS::static)

# Opcional: Instalar el ejecutable
install(TARGETS udpserver DESTINATION bin)