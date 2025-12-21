add_executable(custom main.cc)

set_property(TARGET custom PROPERTY CXX_STANDARD 23)
set_property(TARGET custom PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET custom PROPERTY CXX_EXTENSIONS OFF)

find_package(c-ares CONFIG REQUIRED)
target_link_libraries(custom PRIVATE c-ares::cares)

install(TARGETS custom RUNTIME DESTINATION c-ares)
