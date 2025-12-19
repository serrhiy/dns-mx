add_executable(main main.cc)

set_property(TARGET main PROPERTY CXX_STANDARD 23)
set_property(TARGET main PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET main PROPERTY CXX_EXTENSIONS OFF)

install(TARGETS main RUNTIME DESTINATION .)
