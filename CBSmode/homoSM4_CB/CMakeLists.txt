# file(GLOB test_sources RELATIVE "${CMAKE_CURRENT_LIST_DIR}" "*.cpp")


add_executable(homosm4 SM4.cpp SM4_homo.cpp)
target_link_libraries(homosm4 tfhe++ )

add_executable(homoAES AES.cpp AES_homo.cpp)
target_link_libraries(homoAES tfhe++ )

# foreach(test_source ${test_sources})
#     string( REPLACE ".cpp" "" test_name ${test_source} )
#     add_executable(${test_name} ${test_source})
#     target_link_libraries(${test_name} tfhe++ )
# endforeach(test_source ${test_sources})

# # For GMP used in INTorus test
# find_library(gmp NAMES gmp gmpxx)
# if(gmp)
#     add_compile_definitions(ENABLE_LSHTEST)
#     target_link_libraries(INTorus gmp)
# endif()

# add_subdirectory(axell)