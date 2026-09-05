# Unit tests. Each test is a small standalone executable registered with CTest.

add_executable(buffer_smoke buffer_smoke.cpp)
add_executable(message_test message_test.cpp)
add_executable(framer_test  framer_test.cpp)

# The block substrate lives under src/ as private headers.
foreach(t buffer_smoke message_test framer_test)
    target_include_directories(${t} PRIVATE ${PROJECT_SOURCE_DIR}/src)
    target_link_libraries(${t} PRIVATE taps_static)
    if(UNIX AND NOT APPLE)
        target_link_libraries(${t} PRIVATE pthread)
    endif()
    add_test(NAME ${t} COMMAND ${t})
endforeach()
