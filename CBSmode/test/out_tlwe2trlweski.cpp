#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <tfhe++.hpp>

int main()
{
    constexpr uint32_t num_test = 1000;
    std::random_device seed_gen;
    std::default_random_engine engine(seed_gen());
    std::uniform_int_distribution<uint32_t> binary(0, 1);

    TFHEpp::SecretKey* sk = new TFHEpp::SecretKey();
    std::vector<uint8_t> pa(num_test);
    for (int i = 0; i < num_test; i++) pa[i] = binary(engine) > 0;

    // 定义在level 1情况
    std::vector<TFHEpp::TLWE<TFHEpp::lvl2param>> ca(num_test);

    ca = TFHEpp::bootsSymEncrypt<TFHEpp::lvl2param>(pa, *sk);

    // 切换为level 1 TRLWE
    std::vector<TFHEpp::TRLWE<TFHEpp::lvl1param>> cres(num_test);

    TFHEpp::TLWE2TRLWEIKSKey<TFHEpp::lvl21param>* iksk =
        new TFHEpp::TLWE2TRLWEIKSKey<TFHEpp::lvl21param>();

    TFHEpp::tlwe2trlweikskkgen<TFHEpp::lvl21param>(*iksk, *sk);

    std::chrono::system_clock::time_point start, end;
    start = std::chrono::system_clock::now();

    for (int test = 0; test < num_test; test++) {
        TFHEpp::TLWE2TRLWEIKS<TFHEpp::lvl21param>(cres[test], ca[test], *iksk);
    }

    end = std::chrono::system_clock::now();
    std::vector<std::array<bool, TFHEpp::lvl1param::n>> pres(num_test);
    for (int i = 0; i < num_test; i++)
        pres[i] =
            TFHEpp::trlweSymDecrypt<TFHEpp::lvl1param>(cres[i], sk->key.lvl1);
    for (int i = 0; i < num_test; i++) assert(pres[i][0] == (pa[i] > 0));
    std::cout << "Passed" << std::endl;
    double elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();
    std::cout << elapsed / num_test << "ms" << std::endl;
}