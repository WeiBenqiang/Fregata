cmake_minimum_required(VERSION 3.10)

#g++ homosm4-v3.cpp -O3 -std=c++11 -funroll-all-loops -march=native -I"../tfhe/src/include/" -L"../tfhe/build/libtfhe/" -ltfhe-spqlios-fma -lm -g -o homosm4-v3
project(homosm4)

# set(SRC test.cpp)

# include_directories(../tfhe/src/include)

# link_directories(tfhe-spqlios-fma ../tfhe/build/libtfhe) 库文件的路径

add_compile_options(-O3 -std=c++11 -funroll-all-loops -march=native -lm -g)

add_executable(homosm4_fbs homosm4.cpp)

target_link_libraries(homosm4_fbs tfhe-spqlios-fma)


