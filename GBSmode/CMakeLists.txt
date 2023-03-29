cmake_minimum_required(VERSION 3.12)

project(LOOKUPTABLE)

add_executable(homoSM4 SM4.cpp homosm4.cpp)

target_link_libraries(homoSM4 tfhe-spqlios-fma)

add_executable(homoAES AES.cpp homoAES.cpp)

target_link_libraries(homoAES tfhe-spqlios-fma)
