#include <iostream>
#include <chrono>
#include <tfhe/tfhe_core.h>
#include <tfhe/tfhe.h>
#include <time.h>

using namespace std;

// Test vector
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
// 		   rk[ 8] = a520307c X[ 8] = 27dac07f
// 		   rk[ 9] = b7584dbd X[ 9] = 42dd0f19
// 		   rk[10] = c30753ed X[10] = b8a5da02
// 		   rk[11] = 7ee55b57 X[11] = 907127fa
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

const double clocks2seconds = 1. / CLOCKS_PER_SEC;

/*
 * Expanded SM4 S-boxes
 /* Sbox table: 8bits input convert to 8 bits output*/
extern const unsigned char SboxTable[16][16];

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

void XOR_Two(LweSample **result, LweSample **a, LweSample **b, const TFheGateBootstrappingCloudKeySet *bk,
             TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            bootsXOR(result[i] + j, a[i] + j, b[i] + j, bk);
            // cout<< bootsSymDecrypt(result[i] + j, key) << " ";
        }
        // cout<<endl;
    }
}

void XOR_Four(LweSample **result, LweSample **a, LweSample **b, LweSample **c, LweSample **d,
              const TFheGateBootstrappingCloudKeySet *bk,
              TFheGateBootstrappingSecretKeySet *key)
{
    XOR_Two(result, a, b, bk, key);
    XOR_Two(result, result, c, bk, key);
    XOR_Two(result, result, d, bk, key);
}

void MakeSBoxTable(LweSample **table, TFheGateBootstrappingParameterSet *params,
                   TFheGateBootstrappingSecretKeySet *key)
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

    // make Sbox table: 256 * 8
    for (int j = 0; j < 8; j++)
    {
        table[j] = new_gate_bootstrapping_ciphertext_array(256, params);
        for (int i = 0; i < 256; i++)
        {
            bootsSymEncrypt(table[j] + i, Sbox_binary[i][j], key);
        }
    }
}

//256->128->64->32->16->8-> 4 -> 2 -> 1
void LookupTable(LweSample *result, LweSample *X, LweSample *table,
                 TFheGateBootstrappingParameterSet *params,
                 const TFheGateBootstrappingCloudKeySet *bk,
                 TFheGateBootstrappingSecretKeySet *key)

{
    // x0
    LweSample *ct128 = new_gate_bootstrapping_ciphertext_array(128, params);
    for (int i = 0; i < 128; i++)
    {
        bootsMUX(ct128 + i, X + 0, table + 2 * i + 1, table + 2 * i, bk);
    }

    // x1
    LweSample *ct64 = new_gate_bootstrapping_ciphertext_array(64, params);
    for (int i = 0; i < 64; i++)
    {
        bootsMUX(ct64 + i, X + 1, ct128 + 2 * i + 1, ct128 + 2 * i, bk);
    }

    // x2
    LweSample *ct32 = new_gate_bootstrapping_ciphertext_array(32, params);
    for (int i = 0; i < 32; i++)
    {
        bootsMUX(ct32 + i, X + 2, ct64 + 2 * i + 1, ct64 + 2 * i, bk);
    }
    // x3
    LweSample *ct16 = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i = 0; i < 16; i++)
    {
        bootsMUX(ct16 + i, X + 3, ct32 + 2 * i + 1, ct32 + 2 * i, bk);
    }

    // x4
    LweSample *ct8 = new_gate_bootstrapping_ciphertext_array(8, params);
    for (int i = 0; i < 8; i++)
    {
        bootsMUX(ct8 + i, X + 4, ct16 + 2 * i + 1, ct16 + 2 * i, bk);
    }

    // x5
    LweSample *ct4 = new_gate_bootstrapping_ciphertext_array(4, params);
    for (int i = 0; i < 4; i++)
    {
        bootsMUX(ct4 + i, X + 5, ct8 + 2 * i + 1, ct8 + 2 * i, bk);
    }

    // x6
    LweSample *ct2 = new_gate_bootstrapping_ciphertext_array(2, params);
    for (int i = 0; i < 2; i++)
    {
        bootsMUX(ct2 + i, X + 6, ct4 + 2 * i + 1, ct4 + 2 * i, bk);
    }
    // x7
    bootsMUX(result, X + 7, ct2 + 1, ct2 + 0, bk);

    delete_gate_bootstrapping_ciphertext_array(128, ct128);
    delete_gate_bootstrapping_ciphertext_array(64, ct64);
    delete_gate_bootstrapping_ciphertext_array(32, ct32);
    delete_gate_bootstrapping_ciphertext_array(16, ct16);
    delete_gate_bootstrapping_ciphertext_array(8, ct8);
    delete_gate_bootstrapping_ciphertext_array(4, ct4);
    delete_gate_bootstrapping_ciphertext_array(2, ct2);
}

void Linear_transformation(LweSample **C, LweSample **B, TFheGateBootstrappingParameterSet *params,
                           const TFheGateBootstrappingCloudKeySet *bk,
                           TFheGateBootstrappingSecretKeySet *key)
{
    // L: 𝐶 = 𝐿(𝐵) = 𝐵 ⨁ 𝐵 ⋘ 2 ⨁ 𝐵 ⋘ 10 ⨁ 𝐵 ⋘ 18 ⨁ 𝐵 ⋘ 24
    LweSample *B2[4], *B10[4], *B18[4], *B24[4];
    for (int i = 0; i < 4; i++)
    {
        B2[i] = new_gate_bootstrapping_ciphertext_array(8, params);
        B10[i] = new_gate_bootstrapping_ciphertext_array(8, params);
        B18[i] = new_gate_bootstrapping_ciphertext_array(8, params);
        B24[i] = new_gate_bootstrapping_ciphertext_array(8, params);
        C[i] = new_gate_bootstrapping_ciphertext_array(8, params);
    }
    cout << "=================linear transformation================" << endl;
    // B2 = B <<< 2
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            if (j < 2)
            {
                lweCopy(B2[i] + j, B[(i + 1) % 4] + j + 6, params->in_out_params);
            }
            else
            {
                lweCopy(B2[i] + j, B[i] + j - 2, params->in_out_params);
            }
        }
    }

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            lweCopy(B10[i] + j, B2[(i + 1) % 4] + j, params->in_out_params); // B <<< 10
            lweCopy(B18[i] + j, B2[(i + 2) % 4] + j, params->in_out_params); // B <<< 18
            lweCopy(B24[i] + j, B[(i + 3) % 4] + j, params->in_out_params);  // B <<< 24
            // cout << bootsSymDecrypt(B24[i] + j, key) << " ";
        }
        // cout << endl;
    }

    // 𝐶 = 𝐿(𝐵) = 𝐵⨁ 𝐵 ⋘ 2 ⨁ 𝐵 ⋘ 10 ⨁ 𝐵 ⋘ 18 ⨁ 𝐵 ⋘ 24

    XOR_Four(C, B2, B10, B18, B24, bk, key);
    XOR_Two(C, B, C, bk, key);

#if 0
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            cout << bootsSymDecrypt(C[i] + j, key) << " ";
        }
        cout << endl;
    }
#endif
}

int main()
{
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    // generate a random key
    uint32_t seed[] = {214, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet *key = new_random_gate_bootstrapping_secret_keyset(params);

    const TFheGateBootstrappingCloudKeySet *bk = &(key->cloud);

    int columns = 8;
    LweSample *Table[columns]; 

    cout << " ===============  MakeSBoxTable=============" << endl;
    clock_t make_begin = clock();
    MakeSBoxTable(Table, params, key);
    clock_t make_end = clock();
    double total_time_maketable = 0.0;
    total_time_maketable = make_end - make_end;
    cout << "total_time_maketable:  " << total_time_maketable << endl;

#if 0
    cout<<"================"<<endl;
    for (int i = 0; i < 8; i++)
    {
        for (int j = 0; j < 256; j++)
        {
            cout<< bootsSymDecrypt(Table[i]+j, key)<< " ";
        }
        cout<< endl;
    }
#endif

    //  plain: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    //  key:   01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10

    unsigned char plain[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    unsigned char SM4key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    // We rely on some implementation of this function
    cout << " .........RoundKey ........" << endl;
    // Compute the key expansion
    unsigned long RoundKey[32];
    sm4_setkey(RoundKey, SM4key);

    cout << "==================encrypt X====================" << endl;
    LweSample ***X = new LweSample **[36];
    for (int i = 0; i < 36; i++)
    {
        X[i] = new LweSample *[4];
        for (int j = 0; j < 8; j++)
        {
            X[i][j] = new_gate_bootstrapping_ciphertext_array(8, params);
        }
    }
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
                bootsSymEncrypt(&X[i][j][k], bin_str[k], key);
            }
            // cout << endl;
        }
    }

    LweSample ***rk = new LweSample **[32];
    for (int i = 0; i < 32; i++)
    {
        rk[i] = new LweSample *[4];
        unsigned char a[4];
        PUT_ULONG_BE(RoundKey[i], a, 0);
        for (int j = 0; j < 4; j++)
        {
            int bin_str[8];
            HexToBinStr(a[j], bin_str);
            rk[i][j] = new_gate_bootstrapping_ciphertext_array(8, params);
            for (int k = 0; k < 8; k++)
            {
                // cout << bin_str[k] << " ";
                bootsSymEncrypt(rk[i][j] + k, bin_str[k], key);
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
            dec_bin[j] = bootsSymDecrypt(&rk[0][i][j], key);
        }
        BinStrToHex(dec_hex, dec_bin);
        cout << hex << dec_hex << endl;
    }
    cout << endl;
#endif
    std::chrono::system_clock::time_point start, end;
    double AddRoundKey_totaltime = 0, LUT_totaltime = 0, Linear_totaltime = 0;

    start = std::chrono::system_clock::now();

    for (int round = 0; round < 32; round++)
    {
        cout << "================round " << dec << round << " start==============" << endl;
        // 异或  X1 + X2 + X3 + rk
        // cout << "-------------------Add roundkey--------------------" << endl;
        std::chrono::system_clock::time_point addkey_start, addkey_end;
        addkey_start = std::chrono::system_clock::now();
        XOR_Four(X[round + 4], X[round + 1], X[round + 2], X[round + 3], rk[round], bk, key);
        addkey_end = std::chrono::system_clock::now();
        double add_key_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(addkey_end - addkey_start)
                .count();
        std::cout << " keyu addition one round costs: " << add_key_elapsed << "ms.." << std::endl;
        AddRoundKey_totaltime += add_key_elapsed;

#if 0
        for (int i = 0; i < 4; i++)
        {
            int dec_bin[8];
            int dec_result = 0;
            for (int j = 0; j < 8; j++)
            {
                // cout << bootsSymDecrypt(X[4][i] + j, key) << " "; //should f0 2 c3 9e
                dec_bin[j] = bootsSymDecrypt(X[round + 4][i] + j, key);
            }

            BinStrToHex(dec_result, dec_bin);
            cout << hex << dec_result << " ";
        }
        cout << endl;

#endif

        cout << " ===============SBox=============" << endl;
        LweSample *B[4];

        std::chrono::system_clock::time_point lut_start, lut_end;

        lut_start = std::chrono::system_clock::now();
        for (int i = 0; i < 4; i++)
        {
            B[i] = new_gate_bootstrapping_ciphertext_array(columns, params);
            for (int j = 0; j < columns; j++)
            {
                LookupTable(B[i] + j, X[round + 4][i], Table[j], params, bk, key);
            }
        }
        lut_end = std::chrono::system_clock::now();
        double lut_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(lut_end - lut_start)
                .count();
        std::cout << " Sbox one round costs: " << lut_elapsed << "ms.." << std::endl;
        LUT_totaltime += lut_elapsed;

#if 0
        cout << "======================test Sbox LookupTable====================" << endl;
        for (int i = 0; i < 4; i++)
        {
            int dec_bin[8];
            int dec_result = 0;
            for (int j = 0; j < 8; j++)
            {
                dec_bin[j] = bootsSymDecrypt(B[i] + j, key);
            }
            BinStrToHex(dec_result, dec_bin);
            cout << hex << dec_result << " "; // 应该是18 e9 92 b1
        }
        cout << endl;
#endif

        //(2) 线性变换L: 𝐶 = 𝐿(𝐵) = 𝐵 ⨁ 𝐵 ⋘ 2 ⨁ 𝐵 ⋘ 10 ⨁ 𝐵 ⋘ 18 ⨁ 𝐵 ⋘ 24
        std::chrono::system_clock::time_point Linear_start, Linear_end;

        Linear_start = std::chrono::system_clock::now();
        Linear_transformation(X[round + 4], B, params, bk, key);
        XOR_Two(X[round + 4], X[round + 4], X[round], bk, key);

        Linear_end = std::chrono::system_clock::now();
        double Linear_elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(Linear_end - Linear_start)
                .count();
        std::cout << " Linear transformation+XOR one round costs: " << Linear_elapsed << "ms.." << std::endl;
        Linear_totaltime += Linear_elapsed;

#if 0
        // 验证这轮的结果
        cout << "round " << round << "result is :  ";
        for (int i = 0; i < 4; i++)
        {
            int dec_bin[8];
            int dec_result = 0;
            for (int j = 0; j < 8; j++)
            {
                dec_bin[j] = bootsSymDecrypt(X[round + 4][i] + j, key);
            }
            BinStrToHex(dec_result, dec_bin);
            cout << hex << dec_result << " ";
        }
        cout << endl;
#endif
    }
    end = std::chrono::system_clock::now();
    double elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();

    // LUT_totaltime
    // double AddRoundKey_totaltime = 0, LUT_totaltime = 0, Linear_totaltime = 0;
    std::cout << " key addition_totaltime costs " << AddRoundKey_totaltime << " ms = " << AddRoundKey_totaltime / 1000 << " seconds , account for " << (AddRoundKey_totaltime / elapsed) * 100 << "%;" << std::endl;
    std::cout << " LUT_totaltime costs: " << LUT_totaltime / 1000 << " seconds. " << LUT_totaltime / 60000 << " minutes.., account for " << (LUT_totaltime / elapsed) * 100 << "%;" << std::endl;
    std::cout << " Linear+XOR_totaltime: " << Linear_totaltime << " ms = " << Linear_totaltime / 1000 << " seconds , account for " << (Linear_totaltime / elapsed) * 100 << "%;" << std::endl;

    std::cout << " homoSM4 using gatebootstrapping costs: " << elapsed << "ms = " << elapsed / 60000 << " minutes.." << std::endl;

    // 二、反序变换(在32轮F函数之后)

    // delete all the pointers
    //  delete_gate_bootstrapping_secret_keyset(key);
    //  delete_gate_bootstrapping_parameters(params);
    //  for (int i = 0; i < 16; i++)
    //  {
    //      delete_gate_bootstrapping_ciphertext_array(8, X[i]);
    //  }

    // for (int i = 0; i < 32; i++)
    // {
    //     delete_gate_bootstrapping_ciphertext_array(32, rk[i]);
    // }

    // for (int i = 0; i < columns; i++)
    // {
    //     delete_gate_bootstrapping_ciphertext_array(256, Table[i]);
    // }

    // delete_gate_bootstrapping_ciphertext_array(columns, result);

    return 0;
}
