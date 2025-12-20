add_executable(event-loop main.cc)

set_property(TARGET event-loop PROPERTY CXX_STANDARD 23)
set_property(TARGET event-loop PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET event-loop PROPERTY CXX_EXTENSIONS OFF)

find_package(c-ares CONFIG REQUIRED)
target_link_libraries(event-loop PRIVATE c-ares::cares)

install(TARGETS event-loop RUNTIME DESTINATION c-ares)
