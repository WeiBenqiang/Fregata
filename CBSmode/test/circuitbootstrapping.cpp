/*
 * @Author: Wei Benqiang
 * @Date: 2023-02-07 10:16:49
 * @LastEditors: Do not edit
 * @LastEditTime: 2023-02-15 16:59:08
 * @Description:
 * @FilePath: /tfhepp/test/circuitbootstrapping.cpp
 */
// #include <gperftools/profiler.h>

#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <tfhe++.hpp>

int main()
{
    constexpr uint32_t num_test = 100;
    std::random_device seed_gen;
    std::default_random_engine engine(seed_gen());
    std::uniform_int_distribution<uint32_t> binary(0, 1);

    using iksP = TFHEpp::lvl10param;
    using bkP = TFHEpp::lvl02param;
    using privksP = TFHEpp::lvl21param;

    std::cout << " lwe 1 dimension: " << TFHEpp::lvl10param::domainP::n << std::endl;
    std::cout << " lwe 0 dimension: " << TFHEpp::lvl02param::domainP::n << std::endl;
    std::cout << " lwe 2 dimension: " << TFHEpp::lvl21param::domainP::n << std::endl;

    TFHEpp::SecretKey *sk = new TFHEpp::SecretKey;
    TFHEpp::EvalKey ek;
    ek.emplaceiksk<iksP>(*sk);
    ek.emplacebkfft<bkP>(*sk);
    ek.emplaceprivksk4cb<privksP>(*sk);

    // 生成10个pa，每个都是n=1024的多项式，用于检验正确性
    std::vector<std::array<uint8_t, privksP::targetP::n>> pa(num_test);

    std::vector<std::array<typename privksP::targetP::T, privksP::targetP::n>>
        pmu(num_test);

    // 初始化pa （0,1,0,1,0,1）
    std::vector<uint8_t> pones(num_test);
    std::array<bool, privksP::targetP::n> pres; // 1024

    for (std::array<uint8_t, privksP::targetP::n> &i : pa)
        for (uint8_t &p : i)
            p = binary(engine);

    // 根据pa 初始化 编码为pmu, 这是来自level1的 mu
    for (int i = 0; i < num_test; i++)
        for (int j = 0; j < privksP::targetP::n; j++)
            pmu[i][j] = pa[i][j] ? privksP::targetP::mu : -privksP::targetP::mu;

    // 初始化 pones
    for (int i = 0; i < num_test; i++)
        pones[i] = true;

    // 定义密文类型
    std::vector<TFHEpp::TRLWE<typename privksP::targetP>> ca(num_test);

    std::vector<TFHEpp::TLWE<typename iksP::domainP>> cones(num_test);
    std::vector<TFHEpp::TRGSWFFT<typename privksP::targetP>> bootedTGSW(
        num_test);

    // pmu（pa）系数的多项式加密为ca, 用于检测正确性
    for (int i = 0; i < num_test; i++)
        ca[i] = TFHEpp::trlweSymEncrypt<typename privksP::targetP>(
            pmu[i], privksP::targetP::alpha,
            sk->key.get<typename privksP::targetP>());

    // pones加密为cones
    cones = TFHEpp::bootsSymEncrypt(pones, *sk);

    std::chrono::system_clock::time_point start, end;
    // ProfilerStart("cb.prof");
    start = std::chrono::system_clock::now();

    // cones密文(TLWE)电路自举为bootedTGSW密文（TRGSW）
    for (int test = 0; test < num_test; test++)
    {
        TFHEpp::CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[test],
                                                            cones[test], ek);
    }
    end = std::chrono::system_clock::now();
    // ProfilerStop();
    
    for (int test = 0; test < num_test; test++)
    {
        TFHEpp::trgswfftExternalProduct<typename privksP::targetP>(
            ca[test], ca[test], bootedTGSW[test]);

        pres = TFHEpp::trlweSymDecrypt<typename privksP::targetP>(ca[test],
                                                                  sk->key.lvl1);
        for (int i = 0; i < privksP::targetP::n; i++)
            assert(pres[i] == pa[test][i]);

    }

    std::cout << "Passed" << std::endl;
    double elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();
    std::cout << elapsed / num_test << "ms" << std::endl;
}
