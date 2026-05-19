# Crear ejecutable para tcpserver
add_executable(tcpserver main.cpp)

# Enlazar con la biblioteca TAPS
target_link_libraries(tcpserver PRIVATE TAPS::static)

# Opcional: Instalar el ejecutable
install(TARGETS tcpserver DESTINATION bin)