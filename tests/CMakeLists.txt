# Unit tests. Each test is a small standalone executable registered with CTest.

add_executable(buffer_smoke buffer_smoke.cpp)

# The block substrate lives under src/ as private headers.
target_include_directories(buffer_smoke PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(buffer_smoke PRIVATE taps_static)

if(UNIX AND NOT APPLE)
    target_link_libraries(buffer_smoke PRIVATE pthread)
endif()

add_test(NAME buffer_smoke COMMAND buffer_smoke)
