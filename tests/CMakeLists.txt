# Unit tests. Each test is a small standalone executable registered with CTest.

add_executable(buffer_smoke buffer_smoke.cpp)
add_executable(message_test message_test.cpp)
add_executable(framer_test  framer_test.cpp)
add_executable(security_parameters_test security_parameters_test.cpp)

# The block substrate lives under src/ as private headers.
foreach(t buffer_smoke message_test framer_test security_parameters_test)
    target_include_directories(${t} PRIVATE ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(${t} PRIVATE taps_static)
    if(UNIX AND NOT APPLE)
        target_link_libraries(${t} PRIVATE pthread)
    endif()
    add_test(NAME ${t} COMMAND ${t})
endforeach()

# End-to-end TLS test: needs OpenSSL and throwaway certificates generated into the
# build tree. Only built when TLS support is on.
if(TAPS_WITH_TLS)
    set(_tls_certs
        ${CMAKE_CURRENT_BINARY_DIR}/ca.crt
        ${CMAKE_CURRENT_BINARY_DIR}/srv.crt
        ${CMAKE_CURRENT_BINARY_DIR}/srv.key)
    add_custom_command(
        OUTPUT ${_tls_certs}
        COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/gen_test_certs.sh ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gen_test_certs.sh
        COMMENT "Generating throwaway TLS test certificates"
        VERBATIM)
    add_custom_target(tls_test_certs DEPENDS ${_tls_certs})

    find_package(OpenSSL REQUIRED)
    add_executable(tls_test tls_test.cpp)
    add_dependencies(tls_test tls_test_certs)
    target_include_directories(tls_test PRIVATE ${PROJECT_SOURCE_DIR}/src)
    target_compile_definitions(tls_test PRIVATE
        TLS_TEST_CERT_DIR="${CMAKE_CURRENT_BINARY_DIR}")
    target_link_libraries(tls_test PRIVATE taps_static OpenSSL::SSL OpenSSL::Crypto)
    if(UNIX AND NOT APPLE)
        target_link_libraries(tls_test PRIVATE pthread)
    endif()
    add_test(NAME tls_test COMMAND tls_test)
endif()
