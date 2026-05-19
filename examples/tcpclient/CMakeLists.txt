# Crear ejecutable para tcpclient
add_executable(tcpclient main.cpp)

# Enlazar con la biblioteca TAPS
target_link_libraries(tcpclient PRIVATE TAPS::static)

# Opcional: Instalar el ejecutable
install(TARGETS tcpclient DESTINATION bin)