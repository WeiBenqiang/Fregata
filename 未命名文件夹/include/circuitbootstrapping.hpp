/*
 * @Author: Wei Benqiang
 * @Date: 2023-02-07 10:16:49
 * @LastEditors: Do not edit
 * @LastEditTime: 2023-02-18 19:35:25
 * @Description: 
 * @FilePath: /tfhepp/include/circuitbootstrapping.hpp
 */
#pragma once

#include <cstdint>

#include "cloudkey.hpp"
#include "gatebootstrapping.hpp"
#include "keyswitch.hpp"

namespace TFHEpp {

template <class iksP, class bkP, class privksP>
void CircuitBootstrappingPartial(TRLWE<typename privksP::targetP> &trgswupper,
                                 TRLWE<typename privksP::targetP> &trgswlower,
                                 const TLWE<typename iksP::domainP> &tlwe,
                                 const EvalKey &ek, const uint32_t digit);

template <class iksP, class bkP, class privksP>
void CircuitBootstrapping(TRGSW<typename privksP::targetP> &trgsw,
                          const TLWE<typename iksP::domainP> &tlwe,
                          const EvalKey &ek);

template <class iksP, class bkP, class privksP>
void CircuitBootstrappingFFT(TRGSWFFT<typename privksP::targetP> &trgswfft,
                             const TLWE<typename iksP::domainP> &tlwe,
                             const EvalKey &ek);

template <class iksP, class bkP, class privksP>
void my_CircuitBootstrapping(TRGSW<typename privksP::targetP> &trgsw,
                          const TLWE<typename iksP::domainP> &tlwe,
                          const EvalKey &ek);

template <class iksP, class bkP, class privksP>
void my_CircuitBootstrappingFFT(TRGSWFFT<typename privksP::targetP> &trgswfft,
                             const TLWE<typename iksP::domainP> &tlwe,
                             const EvalKey &ek);      
                                                    
template <class iksP, class bkP, class privksP>
void SM4_CircuitBootstrapping(TRGSW<typename privksP::targetP> &trgsw,
                          const TLWE<typename bkP::domainP> &tlwe,
                          const EvalKey &ek);

template <class iksP, class bkP, class privksP>
void SM4_CircuitBootstrappingFFT(TRGSWFFT<typename privksP::targetP> &trgswfft,
                             const TLWE<typename bkP::domainP> &tlwe,
                             const EvalKey &ek);  


template <class iksP, class bkP, class privksP>
void CircuitBootstrappingFFTInv(
    TRGSWFFT<typename privksP::targetP> &invtrgswfft,
    const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek);

template <class iksP, class bkP, class privksP>
void CircuitBootstrappingFFTwithInvPartial(
    TRLWEInFD<typename privksP::targetP> &trgswfftupper,
    TRLWEInFD<typename privksP::targetP> &trgswfftlower,
    TRLWEInFD<typename privksP::targetP> &invtrgswfftupper,
    TRLWEInFD<typename privksP::targetP> &invtrgswfftlower,
    const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ck,
    const uint32_t digit);

template <class iksP, class bkP, class privksP>
void CircuitBootstrappingFFTwithInv(
    TRGSWFFT<typename privksP::targetP> &trgswfft,
    TRGSWFFT<typename privksP::targetP> &invtrgswfft,
    const TLWE<typename iksP::domainP> &tlwe, const EvalKey &ek);

}  // namespace TFHEpp