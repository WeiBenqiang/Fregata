/*
 * @Author: Wei Benqiang
 * @Date: 2023-02-07 10:16:49
 * @LastEditors: Do not edit
 * @LastEditTime: 2023-02-07 20:04:52
 * @Description: 
 * @FilePath: /tfhepp/include/trlwe.hpp
 */
#pragma once

#include <array>

#include "params.hpp"

namespace TFHEpp {
using namespace std;

template <class P>
TRLWE<P> trlweSymEncryptZero(const double alpha, const Key<P> &key);

template <class P>
TRLWE<P> trlweSymEncrypt(const array<typename P::T, P::n> &p, const double alpha,
                         const Key<P> &key);

template <class P>
TRLWE<P> trlweSymIntEncrypt(const array<typename P::T, P::n> &p, const double alpha,
                            const Key<P> &key);

template <class P>
array<bool, P::n> trlweSymDecrypt(const TRLWE<P> &c, const Key<P> &key);

template <class P>
Polynomial<P> trlweSymIntDecrypt(const TRLWE<P> &c, const Key<P> &key);

template <class P>
void SampleExtractIndex(TLWE<P> &tlwe, const TRLWE<P> &trlwe, const int index);
}  // namespace TFHEpp