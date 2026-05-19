# Crear ejecutable para udpclient
add_executable(udpclient main.cpp)

# Enlazar con la biblioteca TAPS
target_link_libraries(udpclient PRIVATE TAPS::static)

# Opcional: Instalar el ejecutable
install(TARGETS udpclient DESTINATION bin)