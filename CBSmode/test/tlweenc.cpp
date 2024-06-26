/*
 * @Author: Wei Benqiang
 * @Date: 2023-02-18 10:27:51
 * @LastEditors: Do not edit
 * @LastEditTime: 2023-02-18 14:41:55
 * @Description: 
 * @FilePath: /tfhepp/test/tlweenc.cpp
 */
#include <cassert>
#include <iostream>
#include <random>
#include <tfhe++.hpp>
#include <vector>

using namespace TFHEpp;

int main()
{
    constexpr uint32_t num_test = 1000;

    random_device seed_gen;
    default_random_engine engine(seed_gen());
    uniform_int_distribution<uint32_t> binary(0, 1);

    SecretKey sk;

    vector<uint8_t> p(num_test);
    for (uint8_t &i : p) i = binary(engine);
    vector<TLWE<lvl1param>> c(num_test);
    c = bootsSymEncrypt(p, sk);
    vector<uint8_t> p2(num_test);
    p2 = bootsSymDecrypt(c, sk);
    for (int i = 0; i < num_test; i++) assert(p[i] == p2[i]);

    cout << "Passed" << endl;

    c = bootsSymEncryptHalf(p, sk);
    p2 = bootsSymDecrypt(c, sk);

    for (int i = 0; i < num_test; i++) assert(p[i] == p2[i]);

    cout << "Passed Half" << endl;
}