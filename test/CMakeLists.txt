cmake_minimum_required(VERSION 3.12)

project(LOOKUPTABLE)



add_executable(test  homoAES.cpp)

target_link_libraries(test tfhe-spqlios-fma)
