/*
 * @Author: Wei Benqiang
 * @Date: 2023-02-18 10:49:55
 * @LastEditors: Do not edit
 * @LastEditTime: 2023-02-20 15:37:46
 * @Description:
 * @FilePath: /tfhepp/homoSM4_CB/SM4_homo.cpp
 */
#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <tfhe++.hpp>

using namespace std;

using iksP = TFHEpp::lvl10param;
using bkP = TFHEpp::lvl02param;
using privksP = TFHEpp::lvl21param;

using TLWE_0 = TFHEpp::TLWE<typename bkP::domainP>;
using TLWE_1 = TFHEpp::TLWE<typename privksP::targetP>; // level 1

using TRLWE_1 = TFHEpp::TRLWE<typename privksP::targetP>; // level 1

// Test vector 1
// plain: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
// key:   01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
// 	   round key and temp computing result:
// 	       rk[ 0] = f12186f9 X[ 0] = 27fad345
// 		   rk[ 1] = 41662b61 X[ 1] = a18b4cb2
// 		   rk[ 2] = 5a6ab19a X[ 2] = 11c1e22a
// 		   rk[ 3] = 7ba92077 X[ 3] = cc13e2ee
// 		   rk[ 4] = 367360f4 X[ 4] = f87c5bd5
// 		   rk[ 5] = 776a0c61 X[ 5] = 33220757
// 		   rk[ 6] = b6bb89b3 X[ 6] = 77f4c297
// 		   rk[ 7] = 24763151 X[ 7] = 7a96f2eb
// 		   rk[ 8] = a520307c X[ 8] = 27dac07f  //OK

// 		   rk[ 9] = b7584dbd X[ 9] = 42dd0f19  //
// 		   rk[10] = c30753ed X[10] = b8a5da02  // 
// 		   rk[11] = 7ee55b57 X[11] = 907127fa  //
// 		   rk[12] = 6988608c X[12] = 8b952b83
// 		   rk[13] = 30d895b7 X[13] = d42b7c59
// 		   rk[14] = 44ba14af X[14] = 2ffc5831
// 		   rk[15] = 104495a1 X[15] = f69e6888
// 		   rk[16] = d120b428 X[16] = af2432c4
// 		   rk[17] = 73b55fa3 X[17] = ed1ec85e
// 		   rk[18] = cc874966 X[18] = 55a3ba22
// 		   rk[19] = 92244439 X[19] = 124b18aa
// 		   rk[20] = e89e641f X[20] = 6ae7725f
// 		   rk[21] = 98ca015a X[21] = f4cba1f9
// 		   rk[22] = c7159060 X[22] = 1dcdfa10
// 		   rk[23] = 99e1fd2e X[23] = 2ff60603
// 		   rk[24] = b79bd80c X[24] = eff24fdc
// 		   rk[25] = 1d2115b0 X[25] = 6fe46b75
// 		   rk[26] = 0e228aeb X[26] = 893450ad
// 		   rk[27] = f1780c81 X[27] = 7b938f4c
// 		   rk[28] = 428d3654 X[28] = 536e4246
// 		   rk[29] = 62293496 X[29] = 86b3e94f
// 		   rk[30] = 01cf72e5 X[30] = d206965e
// 		   rk[31] = 9124a012 X[31] = 681edf34
// cypher: 68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46

extern void sm4_setkey(unsigned long RoundKey[], unsigned char key[]);

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n, b, i)                      \
    {                                              \
        (b)[(i)] = (unsigned char)((n) >> 24);     \
        (b)[(i) + 1] = (unsigned char)((n) >> 16); \
        (b)[(i) + 2] = (unsigned char)((n) >> 8);  \
        (b)[(i) + 3] = (unsigned char)((n));       \
    }
#endif

/*
  Expanded SM4 S-boxes
  Sbox table: 8bits input convert to 8 bits output
*/
const double clocks2seconds = 1. / CLOCKS_PER_SEC;

static const unsigned char SboxTable[16][16] =
    {
        {0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
        {0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
        {0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
        {0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
        {0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
        {0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
        {0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
        {0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
        {0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},
        {0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
        {0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
        {0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
        {0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
        {0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
        {0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
        {0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}};

// 256->128->64->32->16->8-> 4 -> 2 -> 1
//  组成整个table,完成
void HexToBinStr(int hex, int *bin_str)
{
    for (int i = 0; i < 8; ++i)
    {
        bin_str[i] = hex % 2;
        hex /= 2;
    }
}

void BinStrToHex(int &dex_hex, int *bin_str)
{
    for (int i = 0; i < 8; ++i)
    {
        dex_hex += bin_str[i] * pow(2, i);
    }
}

template <class P>
void XOR_Two(P &result, P &a, P &b)
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            // bootsXOR(result[i] + j, a[i] + j, b[i] + j, bk);
            for (int num = 0; num < bkP::domainP::n + 1; num++)
            {
                result[i][j][num] = a[i][j][num] + b[i][j][num];
            }
        }
        // cout<<endl;
    }
}


template <class P>
void XOR_Four(P &result, P &a, P &b, P &c, P &d)
{
    XOR_Two<P>(result, a, b);
    XOR_Two<P>(result, result, c);
    XOR_Two<P>(result, result, d);
}

// template <class P>
void MakeSBoxTable(std::vector<TRLWE_1> &Table, const TFHEpp::Key<privksP::targetP> &key)
{
    int Sbox_binary[256][8];
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            int bin_str[8];
            HexToBinStr(SboxTable[i][j], bin_str);
            for (int k = 0; k < 8; k++)
            {
                Sbox_binary[i * 16 + j][k] = bin_str[k];
                // cout<< Sbox_binary[i*16+j][k] << " ";
            }
            // cout << endl;
        }
    }

    for (int k = 0; k < 2; k++)
    {
        TFHEpp::Polynomial<typename privksP::targetP> poly;
        for (int i = 0; i < 128; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                poly[i * 8 + j] = (typename privksP::targetP::T)Sbox_binary[k * 128 + i][j];
                // cout << Sbox_binary[k * 128 + i][j] << " ";
            }
            // cout << endl;
        }

        Table[k] = TFHEpp::trlweSymIntEncrypt<privksP::targetP>(poly, privksP::targetP::alpha, key);
    }
}

void LookupTableMixedPacking(TRLWE_1 &result, std::vector<TRLWE_1> &Table, std::vector<TFHEpp::TRGSWFFT<typename privksP::targetP>> &select)
{
    //  TFHEpp::TRGSWFFT<TRLWE_1> select1;
    // TFHEpp::TRLWE<typename privksP::targetP> resultOfCMUX;
    TFHEpp::CMUXFFT<typename privksP::targetP>(result, select[7], Table[1], Table[0]);

    privksP::targetP::T *bara = new privksP::targetP::T[8];

    // level 1
    privksP::targetP::T NX2 = 2 * privksP::targetP::n;
    for (int32_t i = 0; i < 7; i++)
    {
        bara[i] = NX2 - 8 * pow(2, i); 
    }

    TFHEpp::BlindRotate_LUT<privksP>(result, bara, select, 7); 
}

void Linear_transformation(std::vector<std::vector<TLWE_0>> &res, std::vector<std::vector<TLWE_0>> &B)
{
    // 𝐶 = 𝐿(𝐵) = 𝐵 ⨁ 𝐵 ⋘ 2 ⨁ 𝐵 ⋘ 10 ⨁ 𝐵 ⋘ 18 ⨁ 𝐵 ⋘ 24
    // B<<<2  B<<<10  B<<<18  B<<<24
    std::vector<std::vector<TLWE_0>> B2, B10, B18, B24;
    B2.resize(4);
    B10.resize(4);
    B18.resize(4);
    B24.resize(4);
    for (size_t i = 0; i < 4; i++)
    {
        B2[i].resize(8);
        B10[i].resize(8);
        B18[i].resize(8);
        B24[i].resize(8);
    }

    // HomCOPY<typename bkP::domainP>
    // B2 = B <<< 2
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            if (j < 2)
            {
                TFHEpp::HomCOPY<typename bkP::domainP>(B2[i][j], B[(i + 1) % 4][j + 6]);
            }
            else
            {
                TFHEpp::HomCOPY<typename bkP::domainP>(B2[i][j], B[i][j - 2]);
            }
        }
    }

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(B10[i][j], B2[(i + 1) % 4][j]); // B <<< 10
            TFHEpp::HomCOPY<typename bkP::domainP>(B18[i][j], B2[(i + 2) % 4][j]); // B <<< 18
            TFHEpp::HomCOPY<typename bkP::domainP>(B24[i][j], B[(i + 3) % 4][j]);  // B <<< 24
        }
        // cout << endl;
    }
    //  𝐶 = 𝐿(𝐵) = 𝐵⨁ 𝐵 ⋘ 2 ⨁ 𝐵 ⋘ 10 ⨁ 𝐵 ⋘ 18 ⨁ 𝐵 ⋘ 24

    XOR_Four(res, B2, B10, B18, B24);
    XOR_Two(res, B, res);
}

int main()
{
    std::random_device seed_gen;
    std::default_random_engine engine(seed_gen());
    std::uniform_int_distribution<uint32_t> binary(0, 1);

    // Generate key
    TFHEpp::SecretKey *sk = new TFHEpp::SecretKey;
    TFHEpp::EvalKey ek;
    ek.emplaceiksk<iksP>(*sk);
    ek.emplacebkfft<bkP>(*sk);
    ek.emplaceprivksk4cb<privksP>(*sk);

    ek.emplacebkfft<TFHEpp::lvl01param>(*sk); // used for identitybootstrapping

    std::cout << " ==================  开始制作SBox表格=================" << endl;
    std::vector<TRLWE_1> Table(2);
    MakeSBoxTable(Table, sk->key.get<privksP::targetP>()); 

#if 0

    cout << "================" << endl;
    for (int j = 0; j < 2; j++)
    {
        // TorusPolynomial *result = new_TorusPolynomial(N);
        TFHEpp::Polynomial<typename privksP::targetP> pres;
        pres = TFHEpp::trlweSymIntDecrypt<typename privksP::targetP>(Table[j], sk->key.get<typename privksP::targetP>());
        // tLweSymDecrypt(result, Table + j, &key->tgsw_key->tlwe_key, 2);
        for (int i = 0; i < 1024; i++)
        {
            cout << pres[i] << " ";
        }
        cout << endl;
        cout << endl;
        cout << endl;
    }
    return 0;
#endif

    clock_t make_end = clock();
    double total_time_maketable = 0.0;
    total_time_maketable = make_end - make_end;
    cout << "total_time_maketable is : " << total_time_maketable << " microseconds..." << endl;

    //  plain: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    //  key:   01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10

    unsigned char plain[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    unsigned char SM4key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    // We rely on some implementation of this function
    cout << " ..........................RoundKey......................." << endl;
    // Compute the key expansion
    unsigned long RoundKey[32];
    sm4_setkey(RoundKey, SM4key);


    std::cout << " .....................encrypt RoundKey .................... " << endl;
    std::vector<std::vector<std::vector<TLWE_0>>> rk;
    rk.resize(32);

    for (int i = 0; i < 32; i++)
    {
        rk[i].resize(4);
        unsigned char a[4];
        PUT_ULONG_BE(RoundKey[i], a, 0);
        for (int j = 0; j < 4; j++)
        {
            int bin_str[8];
            HexToBinStr(a[j], bin_str);
            rk[i][j].resize(8);
            for (int k = 0; k < 8; k++)
            {
                // cout << bin_str[k] << " ";
                // encrypt TLWE in level 0
                rk[i][j][k] = TFHEpp::tlweSymIntEncrypt<typename bkP::domainP>((typename bkP::domainP::T)bin_str[k], bkP::domainP::alpha,
                                                                               sk->key.get<typename bkP::domainP>());
            }
            // cout << endl;
        }
    }

#if 0
    cout << "================" << endl;
    for (int i = 0; i < 4; i++)
    {
        int dec_hex = 0;
        int dec_bin[8];
        for (int j = 0; j < 8; j++)
        {
            // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
            dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(rk[9][i][j], sk->key.get<typename bkP::domainP>());
            // bootsSymDecrypt(&rk[0][i][j], key);
        }
        BinStrToHex(dec_hex, dec_bin);
        cout << hex << dec_hex << endl;
    }
    cout << endl;

#endif

    cout << "==================encrypt X====================" << endl;
    std::vector<std::vector<std::vector<TLWE_0>>> X;
    X.resize(36);
    for (int i = 0; i < X.size(); i++)
    {
        X[i].resize(4);
        for (int j = 0; j < X[i].size(); j++)
        {
            X[i][j].resize(8);
        }
    }

    // encrypt X[0],X[1],X[2],X[3]
    for (int i = 0; i < 4; i++)
    {
        // X[i] = new LweSample *[4];
        for (int j = 0; j < 4; j++)
        {
            int bin_str[8];
            HexToBinStr(plain[4 * i + j], bin_str);
            // X[i][j] = new_gate_bootstrapping_ciphertext_array(8, params);
            for (int k = 0; k < 8; k++)
            {
                // cout << bin_str[k] << " ";
                // encrypt  TLWE in level 0
                X[i][j][k] = TFHEpp::tlweSymIntEncrypt<typename bkP::domainP>((typename bkP::domainP::T)bin_str[k], bkP::domainP::alpha,
                                                                              sk->key.get<typename bkP::domainP>());
            }
            // cout << endl;
        }
    }

    std::vector<std::vector<TFHEpp::TRGSWFFT<typename privksP::targetP>>> bootedTGSW;
    bootedTGSW.resize(4);
    for (int i = 0; i < 4; i++)
    {
        bootedTGSW[i].resize(8);
    }

    int test_times = 100;
    std::chrono::system_clock::time_point start_total, end_total;
    start_total = std::chrono::system_clock::now();

    std::chrono::system_clock::time_point start, end;
    double cb_totaltime = 0, lut_totaltime = 0, Idboot_totaltime = 0, Idks_totaltime = 0;
    start = std::chrono::system_clock::now();

    for (int round = 0; round < 32; round++)
    {
        // cout << "================round " << dec << round << " start ==============" << endl;
        // clock_t round_begin = clock();
        //   X1 + X2 + X3 + rk
        // cout << "-------------------XOR--------------------" << endl;
        XOR_Four(X[round + 4], X[round + 1], X[round + 2], X[round + 3], rk[round]);

#if 0
        cout << "------------- XOR ----" << endl;
        for (int i = 0; i < 4; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(X[round + 4][i][j], sk->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;
#endif

        // SM4_CircuitBootstrappingFFT
        std::chrono::system_clock::time_point cb_start, cb_end;
        cb_start = std::chrono::system_clock::now();
        // #pragma omp parallel for
        for (int i = 0; i < 4; i++)
        {
            // #pragma omp parallel for num_threads(8)
            for (int j = 0; j < 8; j++)
            {
                // cout << "直接从level 0出发" << endl;
                TFHEpp::SM4_CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[i][j],
                                                                        X[round + 4][i][j], ek);
            }
        }
        cb_end = std::chrono::system_clock::now();
        double cb_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(cb_end - cb_start)
                .count();
        // std::cout << " Circuit bootstrapping(32 times) one round costs: " << cb_elapsed << "ms" << std::endl;


        std::vector<TRLWE_1> lut_result(4); //
        std::chrono::system_clock::time_point lut_start, lut_end;
        lut_start = std::chrono::system_clock::now();
        for (int i = 0; i < 4; i++)
        {
            LookupTableMixedPacking(lut_result[i], Table, bootedTGSW[i]);
        }

        lut_end = std::chrono::system_clock::now();
        double lut_elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(lut_end - lut_start)
                .count();
        // std::cout << " Sbox lookup table one round costs: " << lut_elapsed << "us" << std::endl;

#if 0
        cout << "-------------- lookup table ------------" << endl;
        for (int i = 0; i < 4; i++)
        {
            int dec_bin[8] = {0};
            int dex_hex = 0;

            TFHEpp::Polynomial<typename privksP::targetP> pres;
            pres = TFHEpp::trlweSymIntDecrypt<typename privksP::targetP>(lut_result[i], sk->key.get<typename privksP::targetP>());

            // 输出result
            for (int j = 0; j < 8; j++)
            {
                dec_bin[j] = int(pres[j]);
                // cout << dec_bin[j] << " ";
            }

            BinStrToHex(dex_hex, dec_bin);
            cout << hex << dex_hex << " ";
        }
        cout << endl;

        // return 0;
#endif

        std::vector<std::vector<TLWE_1>> Sbox_value;
        Sbox_value.resize(4);

        for (int i = 0; i < Sbox_value.size(); i++)
        {
            Sbox_value[i].resize(8);
        }

        // SampleExtract on level 1
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                TFHEpp::SampleExtractIndex<typename privksP::targetP>(Sbox_value[i][j], lut_result[i], j);
            }
        }

        std::vector<std::vector<TLWE_0>> ks_value;
        ks_value.resize(4);

        for (int i = 0; i < Sbox_value.size(); i++)
        {
            ks_value[i].resize(8);
        }
        std::chrono::system_clock::time_point ks_start, ks_end;

        ks_start = std::chrono::system_clock::now();
        for (int i = 0; i < 4; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                // level 1 -> level 0
                TFHEpp::IdentityKeySwitch<iksP>(ks_value[i][j], Sbox_value[i][j], ek.getiksk<iksP>());
            }
        }

        ks_end = std::chrono::system_clock::now();
        double ks_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(ks_end - ks_start)
                .count();
        // std::cout << " Identity keyswitch(32 times) one round costs: " << ks_elapsed << "ms" << std::endl;

#if 0
        cout << "=======  IdentityKeySwitch =========" << endl;

        for (int i = 0; i < 4; i++)
        {
            int dec_bin1[8];
            int dex_hex1 = 0;
            for (int j = 0; j < 8; j++)
            {
                typename iksP::targetP::T pres = TFHEpp::tlweSymIntDecrypt<typename iksP::targetP>(ks_value[i][j], sk->key.lvl0);
                dec_bin1[j] = int(pres);
                // cout << dec_bin1[i] << " ";
            }
            BinStrToHex(dex_hex1, dec_bin1);
            cout << " -------result----: " << hex << dex_hex1 << endl;
        }

#endif
        // Linear transformation: 𝐶 = 𝐿(𝐵) = 𝐵 ⨁ 𝐵 ⋘ 2 ⨁ 𝐵 ⋘ 10 ⨁ 𝐵 ⋘ 18 ⨁ 𝐵 ⋘ 24
        Linear_transformation(X[round + 4], ks_value);

        // XOR_Two<TLWE_0>();
        XOR_Two(X[round + 4], X[round + 4], X[round]);

        // Identity refresh on level 2
        std::chrono::system_clock::time_point idboot_start, idboot_end;

        idboot_start = std::chrono::system_clock::now();
        if (round > 5)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 8; j++)
                {
                    IdentityBootstrapping(X[round + 4][i][j], X[round + 4][i][j], ek);
                }
            }
        }
        idboot_end = std::chrono::system_clock::now();
        double idboot_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(idboot_end - idboot_start)
                .count();
        // std::cout << " IdentityBootstrapping(32 times) one round costs: " << idboot_elapsed << "ms" << std::endl;

        // total time
        cb_totaltime += cb_elapsed;
        lut_totaltime += lut_elapsed;
        Idboot_totaltime += idboot_elapsed;
        Idks_totaltime += ks_elapsed;

#if 0
        cout << " ---------------- the round " << dec << round << " result is ";
        for (int i = 0; i < 4; i++)
        {
            int dec_bin1[8];
            int dex_hex1 = 0;
            for (int j = 0; j < 8; j++)
            {
                typename iksP::targetP::T pres = TFHEpp::tlweSymIntDecrypt<typename iksP::targetP>(X[round + 4][i][j], sk->key.lvl0);
                dec_bin1[j] = int(pres);
                // cout << dec_bin1[i] << " ";
            }
            BinStrToHex(dex_hex1, dec_bin1);
            cout << hex << dex_hex1 << " ";
        }
        cout << endl;

        cout << "=======================================================" << endl;

#endif
    }

    end = std::chrono::system_clock::now();
    double elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();

    //     test_times--;
    // }

    // end_total = std::chrono::system_clock::now();
    // double elapsed_total =
    //     std::chrono::duration_cast<std::chrono::milliseconds>(end_total - start_total)
    //         .count();

    std::cout << "Circuitbootstrapping costs: " << cb_totaltime << "ms,  account for " << (cb_totaltime / elapsed) * 100 << "%" << std::endl;
    std::cout << "Lookup table costs: " << lut_totaltime << "us , account for " << (lut_totaltime / 1000 / elapsed) * 100 << "%" << std::endl;
    std::cout << "Idboot costs: " << Idboot_totaltime << "ms ,  account for " << (Idboot_totaltime / elapsed) * 100 << "%" << std::endl;
    std::cout << "Idks costs: " << Idks_totaltime << "ms ,  account for " << (Idks_totaltime / elapsed) * 100 << "%" << std::endl;
    std::cout << "homoSM4 using Circuitbootstrapping costs: " << elapsed << "ms" << std::endl;
    //  std::cout << "homoSM4 using Circuitbootstrapping costs: " << elapsed_total / 100 << "ms" << std::endl;
    return 0;
}