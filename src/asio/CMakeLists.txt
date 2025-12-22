add_executable(asio main.cc)

set_property(TARGET asio PROPERTY CXX_STANDARD 23)
set_property(TARGET asio PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET asio PROPERTY CXX_EXTENSIONS OFF)

find_package(c-ares CONFIG REQUIRED)
target_link_libraries(asio PRIVATE c-ares::cares)

find_package(Boost REQUIRED)
target_link_libraries(asio PRIVATE Boost::boost)

install(TARGETS asio RUNTIME DESTINATION .)
