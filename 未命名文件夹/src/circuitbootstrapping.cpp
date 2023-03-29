#include "circuitbootstrapping.hpp"
#include <chrono>

#include <bits/stdint-uintn.h>

namespace TFHEpp {

template <class iksP, class bkP, class privksP>
void CircuitBootstrappingPartial(TRLWE<typename privksP::targetP> &trgswupper,
                                 TRLWE<typename privksP::targetP> &trgswlower,
                                 const TLWE<typename iksP::domainP> &tlwe,
                                 const EvalKey &ek, const uint32_t digit)
{
    TLWE<typename bkP::domainP> tlwelvl0;
    IdentityKeySwitch<iksP>(tlwelvl0, tlwe, ek.getiksk<iksP>());
    const typename bkP::targetP::T mus2 =
        1ULL << (std::numeric_limits<typename privksP::domainP::T>::digits -
                 (digit + 1) * privksP::targetP::Bgbit - 1);
    Polynomial<typename bkP::targetP> testvec;
    for (int i = 0; i < bkP::targetP::n; i++) testvec[i] = mus2;
    TLWE<typename bkP::targetP> tlwemiddle;
    GateBootstrappingTLWE2TLWEFFT<bkP>(tlwemiddle, tlwelvl0, ek.getbkfft<bkP>(),
                                       testvec);
    tlwemiddle[bkP::targetP::n] += mus2;
    PrivKeySwitch<privksP>(trgswupper, tlwemiddle,
                           ek.getprivksk<privksP>("privksk4cb_0"));
    PrivKeySwitch<privksP>(trgswlower, tlwemiddle,
                           ek.getprivksk<privksP>("privksk4cb_1"));
}
#define INST(iksP, bkP, privksP)                                     \
    template void CircuitBootstrappingPartial<iksP, bkP, privksP>(   \
        TRLWE<typename privksP::targetP> & trgswupper,               \
        TRLWE<typename privksP::targetP> & trgswlower,               \
        const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek, \
        const uint32_t digit)
TFHEPP_EXPLICIT_INSTANTIATION_CIRCUIT_BOOTSTRAPPING(INST)
#undef INST

template <class P>
constexpr Polynomial<typename P::domainP> CBtestvector()
{ 
    Polynomial<typename P::domainP> poly;
    constexpr uint32_t bitwidth = bits_needed<P::targetP::l - 1>();

    // std::cout <<" need bits: " << (int)bitwidth << std::endl;  // 2bits

    for (int i = 0; i < (P::domainP::n >> bitwidth); i++)
        for (int j = 0; j < (1 << bitwidth); j++)
            poly[(i << bitwidth) + j] =
                1ULL << (std::numeric_limits<typename P::domainP::T>::digits -
                         (j + 1) * P::targetP::Bgbit - 1);
    return poly;
}

//================= my test =======================================
template <class P>
constexpr Polynomial<typename P::domainP> my_CBtestvector()
{ 
    Polynomial<typename P::domainP> poly;
    constexpr uint32_t bitwidth = bits_needed<P::targetP::l - 1>();

    // std::cout <<" need bits: " << (int)bitwidth << std::endl;  // 2bits

    for (int i = 0; i < (P::domainP::n >> bitwidth) / 2 ; i++)
        for (int j = 0; j < (1 << bitwidth); j++)
            poly[(i << bitwidth) + j] =
                -(1ULL << (std::numeric_limits<typename P::domainP::T>::digits -
                         (j + 1) * P::targetP::Bgbit - 1));

    for (int i = (P::domainP::n >> bitwidth) / 2; i < (P::domainP::n >> bitwidth); i++)
        for (int j = 0; j < (1 << bitwidth); j++)
            poly[(i << bitwidth) + j] =
                1ULL << (std::numeric_limits<typename P::domainP::T>::digits -
                         (j + 1) * P::targetP::Bgbit - 1);    
    
    return poly;
}

// CIM19
template <class P>
void carpov_CBtestvector_factorization(
        Polynomial<typename P::targetP> &TV_1, Polynomial<typename P::targetP> &TV)
{

    TV_1[0] = TV[0] + TV[P::targetP::n - 1];
    
    for (int i = 1; i < P::targetP::n; i++)
    {
        TV_1[i] = TV[i] - TV[i - 1];
    }

}

template <class bkP, class privksP, uint32_t num_out>
void MultiValueBootstrapping(std::array<TLWE<typename bkP::targetP>, num_out> &res,
    const TLWE<typename bkP::domainP> &tlwe, const BootstrappingKeyFFT<bkP> &bkfft)
{
    std::array<Polynomial<typename bkP::targetP>, num_out> testVector;  

    for (int i = 0; i < num_out; i++)
    {
        for (int j = 0; j < bkP::targetP::n; j++)
        {
            testVector[i][j] = 1ULL << (std::numeric_limits<typename privksP::domainP::T>::digits -
                         (i + 1) * privksP::targetP::Bgbit - 1);
        }
    }

    Polynomial<typename bkP::targetP> TV_0;
    //TV_0 = 1/2 * (1 + x + x^2 + ...+ x^{N-1})
    for (int i = 0; i < bkP::targetP::n; i++)
    {
        TV_0[i] = 1ULL << (std::numeric_limits<typename bkP::targetP::T>::digits - 4);
    }
 
    std::array<Polynomial<typename bkP::targetP>, num_out> TV_1;
    for (int i = 0; i < num_out; i++)
    {
        carpov_CBtestvector_factorization<bkP>(TV_1[i], testVector[i]);
    }

    TRLWE<typename bkP::targetP> acc;
    BlindRotate<bkP, 1>(acc, tlwe, bkfft, TV_0);

    std::array<TRLWE<typename bkP::targetP>, num_out> acc_TV;

    for (int i = 0; i < num_out; i++)
    {
        PolyMulNaieve<typename bkP::targetP>(acc_TV[i][0], acc[0], TV_1[i]);
        PolyMulNaieve<typename bkP::targetP>(acc_TV[i][1], acc[1], TV_1[i]);
        
        SampleExtractIndex<typename bkP::targetP>(res[i], acc_TV[i], 0);
    }
}


template <class iksP, class bkP, class privksP>
void my_CircuitBootstrapping(TRGSW<typename privksP::targetP> &trgsw,
                          const TLWE<typename iksP::domainP> &tlwe,
                          const EvalKey &ek)
{
    TLWE<typename bkP::domainP> tlwelvl0;
    IdentityKeySwitch<iksP>(tlwelvl0, tlwe, ek.getiksk<iksP>());

    std::array<TLWE<typename bkP::targetP>, privksP::targetP::l> temp;

    GateBootstrappingManyLUT<bkP, privksP::targetP::l>(
        temp, tlwelvl0, ek.getbkfft<bkP>(), my_CBtestvector<privksP>());

    for (int i = 0; i < privksP::targetP::l; i++) {
        temp[i][privksP::domainP::k * privksP::domainP::n] +=
            1ULL << (numeric_limits<typename privksP::domainP::T>::digits -
                     (i + 1) * privksP::targetP::Bgbit - 1);
        for (int k = 0; k < privksP::targetP::k + 1; k++)
            PrivKeySwitch<privksP>(
                trgsw[i + k * privksP::targetP::l], temp[i],
                ek.getprivksk<privksP>("privksk4cb_" + std::to_string(k)));
    }
}
#define INST(iksP, bkP, privksP)                            \
    template void my_CircuitBootstrapping<iksP, bkP, privksP>( \
        TRGSW<typename privksP::targetP> & trgsw,           \
        const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek)
TFHEPP_EXPLICIT_INSTANTIATION_MY_CIRCUIT_BOOTSTRAPPING(INST)
#undef INST


template <class iksP, class bkP, class privksP>
void my_CircuitBootstrappingFFT(TRGSWFFT<typename privksP::targetP> &trgswfft,
                             const TLWE<typename iksP::domainP> &tlwe,
                             const EvalKey &ek)
{
    TRGSW<typename privksP::targetP> trgsw;
    my_CircuitBootstrapping<iksP, bkP, privksP>(trgsw, tlwe, ek);

    for (int i = 0; i < (privksP::targetP::k + 1) * privksP::targetP::l; i++)
        for (int j = 0; j < privksP::targetP::k + 1; j++)
            TwistIFFT<typename privksP::targetP>(trgswfft[i][j], trgsw[i][j]);
}
#define INST(iksP, bkP, privksP)                               \
    template void my_CircuitBootstrappingFFT<iksP, bkP, privksP>( \
        TRGSWFFT<typename privksP::targetP> & trgswfft,        \
        const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek)
TFHEPP_EXPLICIT_INSTANTIATION_MY_CIRCUIT_BOOTSTRAPPING(INST)
#undef INST

template <class iksP, class bkP, class privksP>
void SM4_CircuitBootstrapping(TRGSW<typename privksP::targetP> &trgsw,
                          const TLWE<typename bkP::domainP> &tlwelvl0,
                          const EvalKey &ek)
{
    std::array<TLWE<typename bkP::targetP>, privksP::targetP::l> temp;

    GateBootstrappingManyLUT<bkP, privksP::targetP::l>(
        temp, tlwelvl0, ek.getbkfft<bkP>(), my_CBtestvector<privksP>());

    for (int i = 0; i < privksP::targetP::l; i++) {
        temp[i][privksP::domainP::k * privksP::domainP::n] +=
            1ULL << (numeric_limits<typename privksP::domainP::T>::digits -
                     (i + 1) * privksP::targetP::Bgbit - 1);
        for (int k = 0; k < privksP::targetP::k + 1; k++)
            PrivKeySwitch<privksP>(
                trgsw[i + k * privksP::targetP::l], temp[i],
                ek.getprivksk<privksP>("privksk4cb_" + std::to_string(k)));
    }

}
                    

template <class iksP, class bkP, class privksP>
void SM4_CircuitBootstrappingFFT(TRGSWFFT<typename privksP::targetP> &trgswfft,
                             const TLWE<typename bkP::domainP> &tlwe,
                             const EvalKey &ek)
{
    TRGSW<typename privksP::targetP> trgsw;
    SM4_CircuitBootstrapping<iksP, bkP, privksP>(trgsw, tlwe, ek);

    for (int i = 0; i < (privksP::targetP::k + 1) * privksP::targetP::l; i++)
        for (int j = 0; j < privksP::targetP::k + 1; j++)
            TwistIFFT<typename privksP::targetP>(trgswfft[i][j], trgsw[i][j]);
} 
#define INST(iksP, bkP, privksP)                               \
    template void SM4_CircuitBootstrappingFFT<iksP, bkP, privksP>( \
        TRGSWFFT<typename privksP::targetP> & trgswfft,        \
        const TLWE<typename bkP::domainP> &tlwe, const EvalKey &ek)
TFHEPP_EXPLICIT_INSTANTIATION_SM4_CIRCUIT_BOOTSTRAPPING(INST)
#undef INST                          


template <class iksP, class bkP, class privksP>
void CircuitBootstrapping(TRGSW<typename privksP::targetP> &trgsw,
                          const TLWE<typename iksP::domainP> &tlwe,
                          const EvalKey &ek)
{
    TLWE<typename bkP::domainP> tlwelvl0;
    IdentityKeySwitch<iksP>(tlwelvl0, tlwe, ek.getiksk<iksP>());
    
    std::array<TLWE<typename bkP::targetP>, privksP::targetP::l> temp;

    std::chrono::system_clock::time_point start1, end1;
    // // ProfilerStart("cb.prof");
    start1 = std::chrono::system_clock::now();

    GateBootstrappingManyLUT<bkP, privksP::targetP::l>(
        temp, tlwelvl0, ek.getbkfft<bkP>(), CBtestvector<privksP>());
    end1 = std::chrono::system_clock::now();

    // start1 = std::chrono::system_clock::now();
    for (int i = 0; i < privksP::targetP::l; i++) {
        temp[i][privksP::domainP::k * privksP::domainP::n] +=
            1ULL << (numeric_limits<typename privksP::domainP::T>::digits -
                     (i + 1) * privksP::targetP::Bgbit - 1);
        for (int k = 0; k < privksP::targetP::k + 1; k++)
            PrivKeySwitch<privksP>(
                trgsw[i + k * privksP::targetP::l], temp[i],
                ek.getprivksk<privksP>("privksk4cb_" + std::to_string(k)));
    }
}
#define INST(iksP, bkP, privksP)                            \
    template void CircuitBootstrapping<iksP, bkP, privksP>( \
        TRGSW<typename privksP::targetP> & trgsw,           \
        const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek)
TFHEPP_EXPLICIT_INSTANTIATION_CIRCUIT_BOOTSTRAPPING(INST)
#undef INST

template <class iksP, class bkP, class privksP>
void CircuitBootstrappingFFT(TRGSWFFT<typename privksP::targetP> &trgswfft,
                             const TLWE<typename iksP::domainP> &tlwe,
                             const EvalKey &ek)
{
    TRGSW<typename privksP::targetP> trgsw;
    CircuitBootstrapping<iksP, bkP, privksP>(trgsw, tlwe, ek);

    for (int i = 0; i < (privksP::targetP::k + 1) * privksP::targetP::l; i++)
        for (int j = 0; j < privksP::targetP::k + 1; j++)
            TwistIFFT<typename privksP::targetP>(trgswfft[i][j], trgsw[i][j]);
}
#define INST(iksP, bkP, privksP)                               \
    template void CircuitBootstrappingFFT<iksP, bkP, privksP>( \
        TRGSWFFT<typename privksP::targetP> & trgswfft,        \
        const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek)
TFHEPP_EXPLICIT_INSTANTIATION_CIRCUIT_BOOTSTRAPPING(INST)
#undef INST

template <class iksP, class bkP, class privksP>
void CircuitBootstrappingFFTInv(
    TRGSWFFT<typename privksP::targetP> &invtrgswfft,
    const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek)
{
    TLWE<typename iksP::domainP> invtlwe;
    // HomNot
    for (int i = 0; i <= iksP::domainP::n; i++) invtlwe[i] = -tlwe[i];
    CircuitBootstrappingFFT<iksP, bkP, privksP>(invtrgswfft, invtlwe, ek);
}
#define INST(iksP, bkP, privksP)                                  \
    template void CircuitBootstrappingFFTInv<iksP, bkP, privksP>( \
        TRGSWFFT<typename privksP::targetP> & invtrgswfft,        \
        const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek)
TFHEPP_EXPLICIT_INSTANTIATION_CIRCUIT_BOOTSTRAPPING(INST)
#undef INST

template <class iksP, class bkP, class privksP>
void CircuitBootstrappingFFTwithInvPartial(
    TRLWEInFD<typename privksP::targetP> &trgswfftupper,
    TRLWEInFD<typename privksP::targetP> &trgswfftlower,
    TRLWEInFD<typename privksP::targetP> &invtrgswfftupper,
    TRLWEInFD<typename privksP::targetP> &invtrgswfftlower,
    const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek,
    const uint32_t digit)
{
    constexpr std::array<typename privksP::targetP::T, privksP::targetP::l> h =
        hgen<typename privksP::targetP>();
    TRLWE<typename privksP::targetP> trgswupper, trgswlower;
    CircuitBootstrappingPartial<iksP, bkP, privksP>(trgswupper, trgswlower,
                                                    tlwe, ek, digit);
    for (int j = 0; j < 2; j++) {
        TwistIFFT<typename privksP::targetP>(trgswfftupper[j], trgswupper[j]);
        TwistIFFT<typename privksP::targetP>(trgswfftlower[j], trgswlower[j]);
    }
    for (int j = 0; j < privksP::targetP::n; j++) {
        trgswupper[0][j] *= -1;
        trgswupper[1][j] *= -1;
        trgswlower[0][j] *= -1;
        trgswlower[1][j] *= -1;
    }
    trgswupper[0][0] += h[digit];
    trgswlower[1][0] += h[digit];
    for (int j = 0; j < 2; j++) {
        TwistIFFT<typename privksP::targetP>(invtrgswfftupper[j],
                                             trgswupper[j]);
        TwistIFFT<typename privksP::targetP>(invtrgswfftlower[j],
                                             trgswlower[j]);
    }
}
#define INST(iksP, bkP, privksP)                                             \
    template void CircuitBootstrappingFFTwithInvPartial<iksP, bkP, privksP>( \
        TRLWEInFD<typename privksP::targetP> & trgswfftupper,                \
        TRLWEInFD<typename privksP::targetP> & trgswfftlower,                \
        TRLWEInFD<typename privksP::targetP> & invtrgswfftupper,             \
        TRLWEInFD<typename privksP::targetP> & invtrgswfftlower,             \
        const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek,         \
        const uint32_t digit)
TFHEPP_EXPLICIT_INSTANTIATION_CIRCUIT_BOOTSTRAPPING(INST)
#undef INST

template <class iksP, class bkP, class privksP>
void CircuitBootstrappingFFTwithInv(
    TRGSWFFT<typename privksP::targetP> &trgswfft,
    TRGSWFFT<typename privksP::targetP> &invtrgswfft,
    const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek)
{
    constexpr array<typename privksP::targetP::T, privksP::targetP::l> h =
        hgen<typename privksP::targetP>();

    TRGSW<typename privksP::targetP> trgsw;
    CircuitBootstrapping<iksP, bkP, privksP>(trgsw, tlwe, ek);
    for (int i = 0; i < 2 * privksP::targetP::l; i++)
        for (int j = 0; j < 2; j++) {
            TwistIFFT<typename privksP::targetP>(trgswfft[i][j], trgsw[i][j]);
            for (int k = 0; k < privksP::targetP::n; k++) trgsw[i][j][k] *= -1;
        }
    for (int i = 0; i < privksP::targetP::l; i++) {
        trgsw[i][0][0] += h[i];
        trgsw[i + privksP::targetP::l][1][0] += h[i];
    }
    for (int i = 0; i < 2 * privksP::targetP::l; i++)
        for (int j = 0; j < 2; j++)
            TwistIFFT<typename privksP::targetP>(invtrgswfft[i][j],
                                                 trgsw[i][j]);
}
#define INST(iksP, bkP, privksP)                                      \
    template void CircuitBootstrappingFFTwithInv<iksP, bkP, privksP>( \
        TRGSWFFT<typename privksP::targetP> & trgswfft,               \
        TRGSWFFT<typename privksP::targetP> & invtrgswfft,            \
        const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek)
TFHEPP_EXPLICIT_INSTANTIATION_CIRCUIT_BOOTSTRAPPING(INST)
#undef INST

}  // namespace TFHEpp
