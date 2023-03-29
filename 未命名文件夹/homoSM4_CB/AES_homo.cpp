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

// extern void sm4_setkey(unsigned long RoundKey[], unsigned char key[]);
extern long AESKeyExpansion(unsigned char roundKeySchedule[],
                            unsigned char key[], int keyBits);

const double clocks2seconds = 1. / CLOCKS_PER_SEC;

const uint32_t byte_mul2[8] = {0, 0, 0, 0, 0, 0, 0, 0};

// extern unsigned char SboxTable[16][16];
static const unsigned char SboxTable[16][16] =
    {
        // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}; // F


void HexToBinStr(int hex, int *bin_str)
{
    for (int i = 0; i < 8; ++i)
    {
        bin_str[i] = hex % 2;
        hex /= 2;
    }
}

void BinStrToHex(int &dec_hex, int *bin_str)
{
    for (int i = 0; i < 8; ++i)
    {
        dec_hex += bin_str[i] * pow(2, i);
    }
}

template <class P>
void XOR_Two(P &result, P &a, P &b)
{
    for (int i = 0; i < 8; i++)
    {
        for (int num = 0; num < bkP::domainP::n + 1; num++)
        {
            result[i][num] = a[i][num] + b[i][num];
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
    // dec-> bit
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

    // mixpacking
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

void CipherSubBytesMixedPacking(TRLWE_1 &result, std::vector<TRLWE_1> &Table, std::vector<TFHEpp::TRGSWFFT<typename privksP::targetP>> &select)
{
    // last bit
    //  TFHEpp::TRGSWFFT<TRLWE_1> select1;
    // TFHEpp::TRLWE<typename privksP::targetP> resultOfCMUX;
    TFHEpp::CMUXFFT<typename privksP::targetP>(result, select[7], Table[1], Table[0]);

    //BlindRotate_LUT
    privksP::targetP::T *bara = new privksP::targetP::T[8];

    // level 1
    privksP::targetP::T NX2 = 2 * privksP::targetP::n;
    for (int32_t i = 0; i < 7; i++)
    {
        bara[i] = NX2 - 8 * pow(2, i);
    }

    TFHEpp::BlindRotate_LUT<privksP>(result, bara, select, 7); //, resultOfCMUX);
}

void CipherAddRoundKey(std::vector<std::vector<TLWE_0>> &cipher, std::vector<std::vector<TLWE_0>> &rk, int round)
{
    for (int i = 0; i < 16; i++)
    {
        XOR_Two(cipher[i], cipher[i], rk[round * 16 + i]);
    }
}

void CipherShiftRows(std::vector<std::vector<TLWE_0>> &cipher, std::vector<std::vector<TLWE_0>> &B)
{
    //  0  4  8  12                 \    0  4  8  12
    //  1  5  9  13           =======\   5  9  13 1
    //  2  6  10 14           ======-/   10 14 2  6
    //  3  7  11 15                 /    15 3  7  11

    // for (int i = 0; i < 8; i++)
    // {
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[0][i], B[0][i]);
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[1][i], B[5][i]);
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[2][i], B[10][i]);
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[3][i], B[15][i]);

    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[4][i], B[4][i]);
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[5][i], B[9][i]);
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[6][i], B[14][i]);
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[7][i], B[3][i]);

    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[8][i], B[8][i]);
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[9][i], B[13][i]);
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[10][i], B[2][i]);
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[11][i], B[7][i]);

    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[12][i], B[12][i]);
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[13][i], B[1][i]);
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[14][i], B[6][i]);
    //     TFHEpp::HomCOPY<typename bkP::domainP>(cipher[15][i], B[11][i]);
    // }
    for (int j = 0; j < 8; j++)
    {
        for (int i = 0; i < 16; i++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(cipher[i][j], B[(5 * i) % 16][j]);
        }
    }
}

void CipherMul2(std::vector<TLWE_0> &byte, std::vector<TLWE_0> &consByte)
{
    // byte((b7 b6 b5 b4 b3 b2 b1)*x = b6 b5 b4 b3 b2 b1 b0 b7 + 000b7 b70 b7 0
    // consByte = 0000 0000
    std::vector<TLWE_0> temp(8);

    for (int i = 1; i < 8; i++)
    {
        TFHEpp::HomCOPY<typename bkP::domainP>(temp[i], byte[i - 1]);
    }
    TFHEpp::HomCOPY<typename bkP::domainP>(temp[0], byte[7]);

    for (int i = 0; i < 8; i++)
    {
        if (i == 1 || i == 3 || i == 4)
        {
            // 000b7 b70 b7 0
            TFHEpp::HomCOPY<typename bkP::domainP>(consByte[i], byte[7]);
        }
    }
    XOR_Two(byte, temp, consByte);
}

void CipherMixColumns(std::vector<std::vector<TLWE_0>> &cipher, std::vector<TLWE_0> &consByte)
{
    // cout << "==============CipherMixColumns==============" << endl;
    //
    // [02  03  01  01] [ s00  s01  s02  s03]
    // |01  02  03  01| | s10  s11  s12  s13|
    // |01  01  02  03| | s20  s21  s22  s23|
    // [03  01  01  02] [ s30  s31  s32  s33]
    //

    for (int i = 0; i < 4; i++)
    {
        std::vector<TLWE_0> t(8);
        std::vector<TLWE_0> Tmp(8);
        std::vector<TLWE_0> Tm(8);

        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(t[j], cipher[4 * i + 0][j]);
        }
        // Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i]; 
        XOR_Four(Tmp, cipher[4 * i + 0], cipher[4 * i + 1], cipher[4 * i + 2], cipher[4 * i + 3]);

        // Tm = state[0][i] ^ state[1][i];
        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(Tm[j], cipher[4 * i + 0][j]); // t = cipher[0][i]
        }
        XOR_Two(Tm, Tm, cipher[4 * i + 1]);

        // Tm = xtime(Tm)   // 6b->d6
        CipherMul2(Tm, consByte);

        // state[0][i] ^= Tm ^ Tmp;
        XOR_Two(cipher[4 * i + 0], cipher[4 * i + 0], Tm);  // 2
        XOR_Two(cipher[4 * i + 0], cipher[4 * i + 0], Tmp); // 4

        //========================================================================================
        //  Tm = state[1][i] ^ state[2][i];
        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(Tm[j], cipher[4 * i + 1][j]);
        }
        XOR_Two(Tm, Tm, cipher[4 * i + 2]);
        //  Tm = xtime(Tm);
        CipherMul2(Tm, consByte);
        // state[1][i] ^= Tm ^ Tmp;
        XOR_Two(cipher[4 * i + 1], cipher[4 * i + 1], Tm);
        XOR_Two(cipher[4 * i + 1], cipher[4 * i + 1], Tmp);

        //=========================================================================================
        // Tm = state[2][i] ^ state[3][i];
        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(Tm[j], cipher[4 * i + 2][j]);
        }
        XOR_Two(Tm, Tm, cipher[4 * i + 3]);
        // Tm = xtime(Tm);
        CipherMul2(Tm, consByte);
        // state[2][i] ^= Tm ^ Tmp;
        XOR_Two(cipher[4 * i + 2], cipher[4 * i + 2], Tm);
        XOR_Two(cipher[4 * i + 2], cipher[4 * i + 2], Tmp);

        //=========================================================================================
        // Tm = state[3][i] ^ t;
        for (int j = 0; j < 8; j++)
        {
            TFHEpp::HomCOPY<typename bkP::domainP>(Tm[j], cipher[4 * i + 3][j]);
        }
        XOR_Two(Tm, Tm, t);

        // Tm = xtime(Tm);
        CipherMul2(Tm, consByte);
        // state[3][i] ^= Tm ^ Tmp;
        XOR_Two(cipher[4 * i + 3], cipher[4 * i + 3], Tm);
        XOR_Two(cipher[4 * i + 3], cipher[4 * i + 3], Tmp);
    }
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

    std::cout << " ==================  MakeSBoxTable=================" << endl;
    std::vector<TRLWE_1> Table(2);
    MakeSBoxTable(Table, sk->key.get<privksP::targetP>()); // 利用level1的trlwe key

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

    //  plain: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    //  key:   01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10

    unsigned char plain[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                               0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    unsigned char aeskey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    std::vector<TLWE_0> consByte(8);
    for (int i = 0; i < 8; i++)
    {
        // encrypt 0
        consByte[i] = TFHEpp::tlweSymIntEncrypt<typename bkP::domainP>((typename bkP::domainP::T)byte_mul2[i], bkP::domainP::alpha,
                                                                       sk->key.get<typename bkP::domainP>());
    }

    cout << " .........RoundKey........" << endl;
    // Compute the key expansion
    unsigned char RoundKey[240];
    long nRoundKeys = AESKeyExpansion(RoundKey, aeskey, 128);
    cout << " rounds: " << nRoundKeys << endl;


    std::vector<std::vector<TLWE_0>> rk;
    rk.resize(240);
    for (int i = 0; i < 240; i++)
    {
        int bin_str[8];
        rk[i].resize(8);
        HexToBinStr(RoundKey[i], bin_str);

        for (int j = 0; j < 8; j++)
        {
            // cout << bin_str[k] << " ";
            // encrypt TLWE in level 0
            rk[i][j] = TFHEpp::tlweSymIntEncrypt<typename bkP::domainP>((typename bkP::domainP::T)bin_str[j], bkP::domainP::alpha,
                                                                        sk->key.get<typename bkP::domainP>());
            // cout << endl;
        }
    }

    std::vector<std::vector<TLWE_0>> cipher;
    cipher.resize(16);
    for (int i = 0; i < 16; i++)
    {
        cipher[i].resize(8);
    }
    // #pragma omp parallel for
    for (int i = 0; i < 16; i++)
    {
        int bin_str[8];
        HexToBinStr(plain[i], bin_str);
        // #pragma omp parallel for num_threads(8)
        for (int j = 0; j < 8; j++)
        {
            //  cout << bin_str[j]<<" ";
            cipher[i][j] = TFHEpp::tlweSymIntEncrypt<typename bkP::domainP>((typename bkP::domainP::T)bin_str[j], bkP::domainP::alpha,
                                                                            sk->key.get<typename bkP::domainP>());
        }
        // cout <<endl;
    }



    std::chrono::system_clock::time_point start, end;
    double cb_totaltime = 0, lut_totaltime = 0, Idks_totaltime = 0;

    start = std::chrono::system_clock::now();

    CipherAddRoundKey(cipher, rk, 0);
#if 0
    cout << "=============round 0 CipherAddRoundKey============" << endl;
    for (int i = 0; i < 16; i++)
    {
        int dec_hex = 0;
        int dec_bin[8];
        for (int j = 0; j < 8; j++)
        {
            // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
            dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(cipher[i][j], sk->key.get<typename bkP::domainP>());
            // bootsSymDecrypt(&rk[0][i][j], key);
        }
        BinStrToHex(dec_hex, dec_bin);
        cout << hex << dec_hex <<" ";
    }
    cout << endl;

#endif

    std::vector<std::vector<TFHEpp::TRGSWFFT<typename privksP::targetP>>> bootedTGSW;

    bootedTGSW.resize(16);
    for (int i = 0; i < 16; i++)
    {
        bootedTGSW[i].resize(8);
    }

    for (int i = 1; i < 10; i++)
    {
        cout << "================round: " << i << "==================" << endl;
        //  std::cout << ".. circuit bootstrapping...  " << std::endl;
        //======================================================================================
        std::chrono::system_clock::time_point cb_start, cb_end;
        cb_start = std::chrono::system_clock::now();
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
                TFHEpp::SM4_CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[i][j],
                                                                        cipher[i][j], ek);
        }

        cb_end = std::chrono::system_clock::now();
        double cb_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(cb_end - cb_start)
                .count();
        std::cout << " Circuit bootstrapping(16 * 8 times) one round costs: " << cb_elapsed << "ms" << std::endl;
        cb_totaltime += cb_elapsed;

        std::vector<TRLWE_1> lut_result(16); //
        std::chrono::system_clock::time_point lut_start, lut_end;
        lut_start = std::chrono::system_clock::now();
        for (int i = 0; i < 16; i++)
        {
            CipherSubBytesMixedPacking(lut_result[i], Table, bootedTGSW[i]);
        }

        lut_end = std::chrono::system_clock::now();
        double lut_elapsed =
            std::chrono::duration_cast<std::chrono::microseconds>(lut_end - lut_start)
                .count();
        std::cout << " Sbox lookup table one round costs: " << lut_elapsed << "us" << std::endl;
        lut_totaltime += lut_elapsed;

#if 0
        cout << "=============CipherSubBytesMixedPacking============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_bin[8] = {0};
            int dex_hex = 0;

            TFHEpp::Polynomial<typename privksP::targetP> pres;
            pres = TFHEpp::trlweSymIntDecrypt<typename privksP::targetP>(lut_result[i], sk->key.get<typename privksP::targetP>());

            for (int j = 0; j < 8; j++)
            {
                dec_bin[j] = int(pres[j]);
                // cout << dec_bin[j] << " ";
            }

            BinStrToHex(dex_hex, dec_bin);
            cout << hex << dex_hex << " ";
        }
        cout << endl;

#endif

        std::vector<std::vector<TLWE_1>> Sbox_value;
        Sbox_value.resize(16);

        for (int i = 0; i < Sbox_value.size(); i++)
        {
            Sbox_value[i].resize(8);
        }

        // SampleExtract level 1
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                TFHEpp::SampleExtractIndex<typename privksP::targetP>(Sbox_value[i][j], lut_result[i], j);
            }
        }

        std::vector<std::vector<TLWE_0>> B;
        B.resize(16);
        for (int i = 0; i < 16; i++)
        {
            B[i].resize(8);
        }

        std::chrono::system_clock::time_point ks_start, ks_end;
        ks_start = std::chrono::system_clock::now();
        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 8; j++)
            {
                // level 1 -> level 0
                TFHEpp::IdentityKeySwitch<iksP>(B[i][j], Sbox_value[i][j], ek.getiksk<iksP>());
            }
        }

        ks_end = std::chrono::system_clock::now();
        double ks_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(ks_end - ks_start)
                .count();
        std::cout << " Identity keyswitch(16 * 8 times) one round costs: " << ks_elapsed << "ms" << std::endl;
        Idks_totaltime += ks_elapsed;

#if 0
        cout << "=======  IdentityKeySwitch =========" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_bin1[8];
            int dex_hex1 = 0;
            for (int j = 0; j < 8; j++)
            {
                typename iksP::targetP::T pres = TFHEpp::tlweSymIntDecrypt<typename iksP::targetP>(B[i][j], sk->key.lvl0);
                dec_bin1[j] = int(pres);
                // cout << dec_bin1[i] << " ";
            }
            BinStrToHex(dex_hex1, dec_bin1);
            cout << hex << dex_hex1 << " ";
        }

        std::cout << endl;

#endif

        //======================================================================================
        CipherShiftRows(cipher, B);
#if 0
        cout << "=============CipherShiftRows============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(cipher[i][j], sk->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;

#endif

        CipherMixColumns(cipher, consByte);
#if 0
        cout << "=============CipherMixColumns============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(cipher[i][j], sk->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;

#endif

        CipherAddRoundKey(cipher, rk, i);

#if 1
        cout << "=============round " << i << " CipherAddRoundKey============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(cipher[i][j], sk->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;
#endif
    }

    cout << "================第 " << 10 << " 轮==================" << endl;

    // CipherSubBytes();
    std::chrono::system_clock::time_point cb_start, cb_end;
    cb_start = std::chrono::system_clock::now();
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 8; j++)
            TFHEpp::SM4_CircuitBootstrappingFFT<iksP, bkP, privksP>(bootedTGSW[i][j],
                                                                    cipher[i][j], ek);
    }

    cb_end = std::chrono::system_clock::now();
    double cb_elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(cb_end - cb_start)
            .count();
    std::cout << " Circuit bootstrapping(16 * 8 times) one round costs: " << cb_elapsed << "ms" << std::endl;
    cb_totaltime += cb_elapsed;

    std::vector<TRLWE_1> lut_result(16); //
    std::chrono::system_clock::time_point lut_start, lut_end;
    lut_start = std::chrono::system_clock::now();
    for (int i = 0; i < 16; i++)
    {
        CipherSubBytesMixedPacking(lut_result[i], Table, bootedTGSW[i]);
    }

    lut_end = std::chrono::system_clock::now();
    double lut_elapsed =
        std::chrono::duration_cast<std::chrono::microseconds>(lut_end - lut_start)
            .count();
    std::cout << " Sbox lookup table one round costs: " << lut_elapsed << "us" << std::endl;
    lut_totaltime += lut_elapsed;

#if 0
    cout << "=============CipherSubBytesMixedPacking============" << endl;
    for (int i = 0; i < 16; i++)
    {
        int dec_bin[8] = {0};
        int dex_hex = 0;

        TFHEpp::Polynomial<typename privksP::targetP> pres;
        pres = TFHEpp::trlweSymIntDecrypt<typename privksP::targetP>(lut_result[i], sk->key.get<typename privksP::targetP>());

        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = int(pres[j]);
            // cout << dec_bin[j] << " ";
        }

        BinStrToHex(dex_hex, dec_bin);
        cout << hex << dex_hex << " ";
    }
    cout << endl;

#endif

    std::vector<std::vector<TLWE_1>> Sbox_value;
    Sbox_value.resize(16);

    for (int i = 0; i < Sbox_value.size(); i++)
    {
        Sbox_value[i].resize(8);
    }

    // SampleExtract level 1
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 8; j++)
        {

            TFHEpp::SampleExtractIndex<typename privksP::targetP>(Sbox_value[i][j], lut_result[i], j);
        }
    }

    // Key Switch to LWE B  on level 0
    std::vector<std::vector<TLWE_0>> B;
    B.resize(16);
    for (int i = 0; i < 16; i++)
    {
        B[i].resize(8);
    }

    std::chrono::system_clock::time_point ks_start, ks_end;

    ks_start = std::chrono::system_clock::now();
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            // level 1 -> level 0
            TFHEpp::IdentityKeySwitch<iksP>(B[i][j], Sbox_value[i][j], ek.getiksk<iksP>());
        }
    }

    ks_end = std::chrono::system_clock::now();
    double ks_elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(ks_end - ks_start)
            .count();
    std::cout << " Identity keyswitch(16 * 8 times) one round costs: " << ks_elapsed << "ms" << std::endl;
    Idks_totaltime += ks_elapsed;

#if 0
        cout << "=======  IdentityKeySwitch =========" << endl;
        // 输出result
        for (int i = 0; i < 16; i++)
        {
            int dec_bin1[8];
            int dex_hex1 = 0;
            for (int j = 0; j < 8; j++)
            {
                typename iksP::targetP::T pres = TFHEpp::tlweSymIntDecrypt<typename iksP::targetP>(B[i][j], sk->key.lvl0);
                dec_bin1[j] = int(pres);
                // cout << dec_bin1[i] << " ";
            }
            BinStrToHex(dex_hex1, dec_bin1);
            cout << hex << dex_hex1 << " ";
        }

        std::cout << endl;

#endif

    //======================================================================================

    CipherShiftRows(cipher, B);
#if 0
        cout << "=============CipherShiftRows============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_hex = 0;
            int dec_bin[8];
            for (int j = 0; j < 8; j++)
            {
                // typename P::T a = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>();
                dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(cipher[i][j], sk->key.get<typename bkP::domainP>());
                // bootsSymDecrypt(&rk[0][i][j], key);
            }
            BinStrToHex(dec_hex, dec_bin);
            cout << hex << dec_hex << " ";
        }
        cout << endl;

#endif
    CipherAddRoundKey(cipher, rk, 10);

    end = std::chrono::system_clock::now();
    double elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();

#if 1
    cout << "=============test last round ============" << endl;
    for (int i = 0; i < 16; i++)
    {
        int dec_hex = 0;
        int dec_bin[8];
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = TFHEpp::tlweSymIntDecrypt<typename bkP::domainP>(cipher[i][j], sk->key.get<typename bkP::domainP>());
        }
        BinStrToHex(dec_hex, dec_bin);
        cout << hex << dec_hex << " ";
    }
    cout << endl;

#endif

    std::cout << "Circuitbootstrapping costs: " << cb_totaltime << "ms,  account for " << (cb_totaltime / elapsed) * 100 << "%" << std::endl;
    std::cout << "Lookup table costs: " << lut_totaltime << "us , account for " << (lut_totaltime / 1000 / elapsed) * 100 << "%" << std::endl;
    std::cout << "Idks costs: " << Idks_totaltime << "ms ,  account for " << (Idks_totaltime / elapsed) * 100 << "%" << std::endl;
    std::cout << "homoAES using Circuitbootstrapping costs: " << elapsed << "ms" << std::endl;

    return 0;
}