project(pipe_test C CXX)

file(GLOB CPP_FILES src/*.c)

# add_definitions(${A_DEFINITIONS})
#
include_directories(${nng_INCLUDE_DIRS})

add_executable(${PROJECT_NAME} ${CPP_FILES})

target_link_libraries(${PROJECT_NAME} nng)
