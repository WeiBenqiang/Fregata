/*
 * @Author: Wei Benqiang
 * @Date: 2023-02-07 10:16:49
 * @LastEditors: Do not edit
 * @LastEditTime: 2023-02-18 17:09:17
 * @Description:
 * @FilePath: /tfhepp/test/my_circuitbootstrapping.cpp
 */
// #include <gperftools/profiler.h>

#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <tfhe++.hpp>

int main()
{
    constexpr uint32_t num_test = 10;
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
    // std::array<数据类型， 数据个数>
    std::vector<std::array<typename privksP::targetP::T, privksP::targetP::n>> pa(num_test);
    // 初始化pa
    for (std::array<typename privksP::targetP::T, privksP::targetP::n> &i : pa)
        for (typename privksP::targetP::T &p : i)
            p = binary(engine);
    
    //用于自举的Tlwe pones 明文
    std::vector<typename iksP::domainP::T> pones(num_test);
    //结果: 明文pres
    std::array<typename privksP::targetP::T, privksP::targetP::n> pres; // 1024

    // 初始化 pones
    for (int i = 0; i < num_test; i++)
        pones[i] = true;

    // 定义密文类型
    std::vector<TFHEpp::TRLWE<typename privksP::targetP>> ca(num_test);
    
    // trlwe的加密  trlweSymIntEncrypt  phase = P::delta * p[i]
    // 用于检测正确性
    for (int i = 0; i < num_test; i++)
        ca[i] = TFHEpp::trlweSymIntEncrypt<typename privksP::targetP>(
            pa[i], privksP::targetP::alpha, sk->key.get<typename privksP::targetP>());

    // 密文处于level 1
    std::vector<TFHEpp::TLWE<typename iksP::domainP>> cones(num_test);

    std::vector<TFHEpp::TRGSWFFT<typename privksP::targetP>> bootedTGSW(
        num_test);

    // tlwe的加密  
    // 加密整个pones数组为 cones
    std::cout <<"delta: " << iksP::domainP::delta << std::endl;

    for (int i = 0; i < pones.size(); i++)
    {
        cones[i] = TFHEpp::tlweSymIntEncrypt<typename iksP::domainP>(pones[i], iksP::domainP::alpha,
                                                             sk->key.get<typename iksP::domainP>());
    }

    std::chrono::system_clock::time_point start, end;
    // ProfilerStart("cb.prof");
    start = std::chrono::system_clock::now();

    // cones密文(TLWE)电路自举为bootedTGSW密文（TRGSW）
    for (int test = 0; test < num_test; test++) {
        TFHEpp::my_CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[test],
                                                            cones[test], ek);
    }
    
    end = std::chrono::system_clock::now();
    // ProfilerStop();

    for (int test = 0; test < num_test; test++) {
        TFHEpp::trgswfftExternalProduct<typename privksP::targetP>(
            ca[test], ca[test], bootedTGSW[test]);

        pres = TFHEpp::trlweSymIntDecrypt<typename privksP::targetP>(ca[test],
                                                                  sk->key.lvl1);
        for (int i = 0; i < privksP::targetP::n; i++)
        {
            assert(pres[i] == pa[test][i]);
        }
    }

    std::cout << "Passed" << std::endl;
    double elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();
    std::cout << elapsed / num_test << "ms" << std::endl;
}
