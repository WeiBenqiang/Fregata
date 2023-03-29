#pragma once

#include <bits/stdint-uintn.h>

#include <cmath>
#include <limits>

#include "cloudkey.hpp"
#include "detwfa.hpp"
#include "keyswitch.hpp"
#include "params.hpp"
#include "trlwe.hpp"
#include "utils.hpp"

namespace TFHEpp {

template <class P, uint32_t num_out = 1>
void BlindRotate(TRLWE<typename P::targetP> &res,
                 const TLWE<typename P::domainP> &tlwe,
                 const BootstrappingKeyFFT<P> &bkfft,
                 const Polynomial<typename P::targetP> &testvector)
{
    constexpr uint32_t bitwidth = bits_needed<num_out - 1>();
    const uint32_t  b_bar = 2 * P::targetP::n -
                       ((tlwe[P::domainP::k * P::domainP::n] >>
                         (std::numeric_limits<typename P::domainP::T>::digits -
                          1 - P::targetP::nbit + bitwidth))
                        << bitwidth);
    res = {};
    PolynomialMulByXai<typename P::targetP>(res[P::targetP::k], testvector, b_bar);
    for (int i = 0; i < P::domainP::k * P::domainP::n; i++) {
        constexpr typename P::domainP::T roundoffset =
            1ULL << (std::numeric_limits<typename P::domainP::T>::digits - 2 -
                     P::targetP::nbit + bitwidth);
        const uint32_t a_bar =
            (tlwe[i] + roundoffset) >>
            (std::numeric_limits<typename P::domainP::T>::digits - 1 -
             P::targetP::nbit + bitwidth)
                << bitwidth;
        if (a_bar == 0) continue;
        // Do not use CMUXFFT to avoid unnecessary copy.
        CMUXFFTwithPolynomialMulByXaiMinusOne<typename P::targetP>(res,
                                                                   bkfft[i], a_bar);
    }
}

template <class P, uint32_t num_out = 1>
void BlindRotate(TRLWE<typename P::targetP> &res,
                 const TLWE<typename P::domainP> &tlwe,
                 const BootstrappingKeyFFT<P> &bkfft,
                 const TRLWE<typename P::targetP> &testvector)
{
    constexpr uint32_t bitwidth = bits_needed<num_out - 1>();
    const uint32_t b_bar = 2 * P::targetP::n -
                       ((tlwe[P::domainP::k * P::domainP::n] >>
                         (std::numeric_limits<typename P::domainP::T>::digits -
                          1 - P::targetP::nbit + bitwidth))
                        << bitwidth);
    for (int k = 0; k < P::targetP::k + 1; k++)
        PolynomialMulByXai<typename P::targetP>(res[k], testvector[k], b_bar);
    for (int i = 0; i < P::domainP::k * P::domainP::n; i++) {
        constexpr typename P::domainP::T roundoffset =
            1ULL << (std::numeric_limits<typename P::domainP::T>::digits - 2 -
                     P::targetP::nbit + bitwidth);
        const uint32_t a_bar =
            (tlwe[i] + roundoffset) >>
            (std::numeric_limits<typename P::domainP::T>::digits - 1 -
             P::targetP::nbit + bitwidth)
                << bitwidth;
        if (a_bar == 0) continue;
        // Do not use CMUXFFT to avoid unnecessary copy.
        CMUXFFTwithPolynomialMulByXaiMinusOne<typename P::targetP>(res,
                                                                   bkfft[i], a_bar);
    }
}

// P = typename privksP::targetP  level 1的参数
template <class P, uint32_t num_out = 1>
void BlindRotate_LUT(TRLWE<typename P::targetP> &res,
                //  const TLWE<typename P::domainP> &tlwe,
                //  const uint32_t *bara,
                const  typename P::targetP::T *a_bar,
                //  const BootstrappingKeyFFT<P> &bkfft,
                std::vector<TFHEpp::TRGSWFFT<typename P::targetP>> &select,
                int n)
                // const TRLWE<typename P::targetP> &testvector)
{
    // constexpr uint32_t bitwidth = bits_needed<num_out - 1>();
    // const uint32_t b_bar = 2 * P::targetP::n -
    //                    ((tlwe[P::domainP::k * P::domainP::n] >>
    //                      (std::numeric_limits<typename P::domainP::T>::digits -
    //                       1 - P::targetP::nbit + bitwidth))
    //                     << bitwidth);
    // for (int k = 0; k < P::targetP::k + 1; k++)
    //     PolynomialMulByXai<typename P::targetP>(res[k], testvector[k], b_bar);

    // std::cout << " lookup table using blindrotation " << std::endl;
    for (int i = 0; i < n; i++) {
        // constexpr typename P::domainP::T roundoffset =
        //     1ULL << (std::numeric_limits<typename P::domainP::T>::digits - 2 -
        //              P::targetP::nbit + bitwidth);
        // const uint32_t a_bar =
        //     (tlwe[i] + roundoffset) >>
        //     (std::numeric_limits<typename P::domainP::T>::digits - 1 -
        //      P::targetP::nbit + bitwidth)
        //         << bitwidth;
        if (a_bar == 0) continue;
        // Do not use CMUXFFT to avoid unnecessary copy.
        CMUXFFTwithPolynomialMulByXaiMinusOne<typename P::targetP>(res,
                                                                   select[i], a_bar[i]);
    }
}

template <class P, uint32_t num_out = 1>
void BlindRotate(TRLWE<typename P::targetP> &res,
                 const TLWE<typename P::domainP> &tlwe,
                 const BootstrappingKeyNTT<P> &bkntt,
                 const Polynomial<typename P::targetP> &testvector)
{
    constexpr uint32_t bitwidth = bits_needed<num_out - 1>();
    const uint32_t b_bar = 2 * P::targetP::n -
                       ((tlwe[P::domainP::k * P::domainP::n] >>
                         (std::numeric_limits<typename P::domainP::T>::digits -
                          1 - P::targetP::nbit + bitwidth))
                        << bitwidth);
    res = {};
    PolynomialMulByXai<typename P::targetP>(res[P::targetP::k], testvector, b_bar);
    for (int i = 0; i < P::domainP::k * P::domainP::n; i++) {
        constexpr typename P::domainP::T roundoffset =
            1ULL << (std::numeric_limits<typename P::domainP::T>::digits - 2 -
                     P::targetP::nbit + bitwidth);
        const uint32_t a_bar =
            (tlwe[i] + roundoffset) >>
            (std::numeric_limits<typename P::domainP::T>::digits - 1 -
             P::targetP::nbit + bitwidth)
                << bitwidth;
        if (a_bar == 0) continue;
        // Do not use CMUXNTT to avoid unnecessary copy.
        CMUXNTTwithPolynomialMulByXaiMinusOne<typename P::targetP>(res,
                                                                   bkntt[i], a_bar);
    }
}

template <class P>
void GateBootstrappingTLWE2TLWEFFT(
    TLWE<typename P::targetP> &res, const TLWE<typename P::domainP> &tlwe,
    const BootstrappingKeyFFT<P> &bkfft,
    const Polynomial<typename P::targetP> &testvector);

template <class P>
void GateBootstrappingTLWE2TLWENTT(
    TLWE<typename P::targetP> &res, const TLWE<typename P::domainP> &tlwe,
    const BootstrappingKeyNTT<P> &bkntt,
    const Polynomial<typename P::targetP> &testvector){
        TRLWE<typename P::targetP> acc;
        BlindRotate<P>(acc, tlwe, bkntt, testvector);
        SampleExtractIndex<typename P::targetP>(res, acc, 0);
    }

template <class P, uint32_t num_out>
void GateBootstrappingManyLUT(
    std::array<TLWE<typename P::targetP>, num_out> &res,
    const TLWE<typename P::domainP> &tlwe, const BootstrappingKeyFFT<P> &bkfft,
    const Polynomial<typename P::targetP> &testvector)
{
    TRLWE<typename P::targetP> acc;
    BlindRotate<P, num_out>(acc, tlwe, bkfft, testvector);
    for (int i = 0; i < num_out; i++)
        SampleExtractIndex<typename P::targetP>(res[i], acc, i);
}

template <class P>
void GateBootstrappingTLWE2TLWEFFTfunc(
    TLWE<typename P::targetP> &res, const TLWE<typename P::domainP> &tlwe,
    const BootstrappingKeyFFT<P> &bkfft,
    const TRLWE<typename P::targetP> &testvector);

template <class P, typename P::T mu>
constexpr Polynomial<P> mupolygen()
{
    Polynomial<P> poly;
    for (typename P::T &p : poly) p = mu;
    return poly;
}

template <typename lvl1param::T mu = lvl1param::mu>
void GateBootstrapping(TLWE<lvl0param> &res, const TLWE<lvl0param> &tlwe,
                       const EvalKey &ek)
{
    TLWE<lvl1param> tlwelvl1;
    GateBootstrappingTLWE2TLWEFFT<lvl01param>(tlwelvl1, tlwe, *ek.bkfftlvl01,
                                              mupolygen<lvl1param, mu>());
    IdentityKeySwitch<lvl10param>(res, tlwelvl1, *ek.iksklvl10);
}

// level 0上的identity bootstrapping
template <typename lvl1param::T mu = lvl1param::mu>
void IdentityBootstrapping(TLWE<lvl0param> &res, const TLWE<lvl0param> &tlwe,
                       const EvalKey &ek)
{
    TLWE<lvl1param> tlwelvl1;   //抽取出来的， 然后密钥切换回去
    //自己设计测试多项式
    Polynomial<lvl1param> identityPoly;
    // std::cout << "dim : " << (int) lvl1param::n<< std::endl;
 
    // 需要满足负循环
    lvl1param::T delta =  1U << 30;

    // std::cout << "delta: " << delta << std::endl;
    // std::cout << "- delta: " << -delta<< std::endl;
    for (int i = 0; i < lvl1param::n / 2; i++)
    {
        identityPoly[i] = -delta;
    }

    for (int i = lvl1param::n / 2; i < lvl1param::n; i++)
    {
        identityPoly[i] = delta;
    }

    GateBootstrappingTLWE2TLWEFFT<lvl01param>(tlwelvl1, tlwe, *ek.bkfftlvl01,
                                            identityPoly);
                                            //   mupolygen<lvl1param, mu>());

    // 补上identityPoly[i] = lvl0param::delta / 2;
    tlwelvl1[lvl1param::k * lvl1param::n] += delta;

    IdentityKeySwitch<lvl10param>(res, tlwelvl1, *ek.iksklvl10);
}


template <typename lvl1param::T mu = lvl1param::mu>
void GateBootstrapping(TLWE<lvl1param> &res, const TLWE<lvl1param> &tlwe,
                       const EvalKey &ek)
{
    TLWE<lvl0param> tlwelvl0;
    IdentityKeySwitch<lvl10param>(tlwelvl0, tlwe, *ek.iksklvl10);
    GateBootstrappingTLWE2TLWEFFT<lvl01param>(res, tlwelvl0, *ek.bkfftlvl01,
                                              mupolygen<lvl1param, mu>());
}

template <typename lvl1param::T mu = lvl1param::mu>
void GateBootstrappingNTT(TLWE<lvl0param> &res, const TLWE<lvl0param> &tlwe,
                       const EvalKey &ek)
{
    TLWE<lvl1param> tlwelvl1;
    GateBootstrappingTLWE2TLWENTT<lvl01param>(tlwelvl1, tlwe, *ek.bknttlvl01,
                                              mupolygen<lvl1param, mu>());
    IdentityKeySwitch<lvl10param>(res, tlwelvl1, *ek.iksklvl10);
}

template <typename lvl1param::T mu = lvl1param::mu>
void GateBootstrappingNTT(TLWE<lvl1param> &res, const TLWE<lvl1param> &tlwe,
                       const EvalKey &ek)
{
    TLWE<lvl0param> tlwelvl0;
    IdentityKeySwitch<lvl10param>(tlwelvl0, tlwe, *ek.iksklvl10);
    GateBootstrappingTLWE2TLWENTT<lvl01param>(res, tlwelvl0, *ek.bknttlvl01,
                                              mupolygen<lvl1param, mu>());
}
}  // namespace TFHEpp