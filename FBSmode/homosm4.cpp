#include <stdio.h>
#include <unistd.h>
#include <chrono>
#include "functional_bootstrap.cpp"
#include "SM4.cpp"

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

void HexToTwobit(int hex, int *bin_str)
{
    for (int i = 0; i < 4; ++i)
    {
        bin_str[i] = hex % 4;
        hex /= 4;
    }
}

void TwobitToHex(int &dec_hex, int *bin_str)
{
    for (int i = 0; i < 4; ++i)
    {
        dec_hex += bin_str[i] * pow(4, i);
    }
}

// extern unsigned char SboxTable[16][16];

void test_2bitXOR(fbt_integer *xor_output, int j, fbt_integer *input, IntPolynomial *xorlut_clear, TFheFunctionalBootstrappingSecretKeySet *key, fbt_context *context)
{
    // printf("============================");
    const TFheGateBootstrappingParameterSet *params = context->params;
    // int f_l3a[3] = {fbt_op_load_hardcoded_LUT, 0, 0};    // this LUT is hardcoded at line 28 of functional_bootstrap.cpp and implements the identity
    // int f_l3b[4] = {fbt_op_generate_mv_b_LUT, 0, 0, 16}; // load the LUTs in polynomials  


    int f_l3c[1] = {fbt_op_mv_f_bootstrap_init};     // Carpov multi value bootstrap first phase
    int f_l3d[4] = {fbt_op_mv_f_bootstrap, 0, 0, 4}; // Carpov multi value bootstrap second phase
    int f_l3e[1] = {fbt_op_next_tree_level};         // next level of the tree evaluation

    // int f_l2a[4] = {fbt_op_tlwe_keyswitch, 0, 0, 4}; // tlwe to trlwe packing.
    // int f_l2b[4] = {fbt_op_f_bootstrap, 0, 0, 4};    // 12 functional bootstraps
    // int f_l2c[1] = {fbt_op_next_tree_level};          // next level of the tree evaluation

    int f_l1a[4] = {fbt_op_tlwe_keyswitch, 0, 0, 1}; // tlwe to trlwe packing
    int f_l1b[4] = {fbt_op_f_bootstrap, 0, 0, 1};    // 3 functional bootstraps
    // int *function[7] = {f_l3a, f_l3b, f_l3c, f_l3d, f_l3e, f_l1a, f_l1b};
    int *function[5] = {f_l3c, f_l3d, f_l3e, f_l1a, f_l1b};

    // fbt_main_loopXOR(function, 7, input->lwe_samples, context); // Execute everything defined in "function"
    fbt_main_loopXOR(function, 5, input->lwe_samples, xorlut_clear, context); // Execute everything defined in "function"

    lweKeySwitch(&xor_output->lwe_samples[j], key->cloud_key->bk->ks, &context->output[0]);
}

void test_LUT_8_bit_to_8_bit(fbt_integer *output, fbt_integer *input, IntPolynomial *Sboxlut_clear, TFheFunctionalBootstrappingSecretKeySet *key, fbt_context *context)
{
    const TFheGateBootstrappingParameterSet *params = context->params;
    // int f_l3a[3] = {fbt_op_load_hardcoded_LUT, 0, 0};      // this LUT is hardcoded at line 28 of functional_bootstrap.cpp and implements the identity
    // int f_l3b[4] = {fbt_op_generate_mv_b_LUT, 0, 0, 1024}; // load the LUTs in polynomials
    int f_l3c[1] = {fbt_op_mv_f_bootstrap_init};       // Carpov multi value bootstrap first phase
    int f_l3d[4] = {fbt_op_mv_f_bootstrap, 0, 0, 256}; // Carpov multi value bootstrap second phase
    int f_l3e[1] = {fbt_op_next_tree_level};           // next level of the tree evaluation

    int f_l2a[4] = {fbt_op_tlwe_keyswitch, 0, 0, 64}; // tlwe to trlwe packing.
    int f_l2b[4] = {fbt_op_f_bootstrap, 0, 0, 64};    // 12 functional bootstraps
    int f_l2c[1] = {fbt_op_next_tree_level};          // next level of the tree evaluation

    int f_l2d[4] = {fbt_op_tlwe_keyswitch, 0, 0, 16}; // tlwe to trlwe packing.
    int f_l2e[4] = {fbt_op_f_bootstrap, 0, 0, 16};    // 12 functional bootstraps
    int f_l2f[1] = {fbt_op_next_tree_level};          // next level of the tree evaluation

    int f_l1a[4] = {fbt_op_tlwe_keyswitch, 0, 0, 4}; // tlwe to trlwe packing
    int f_l1b[4] = {fbt_op_f_bootstrap, 0, 0, 4};    // 3 functional bootstraps
    // int *function[13] = {f_l3a, f_l3b, f_l3c, f_l3d, f_l3e, f_l2a, f_l2b, f_l2c, f_l2d, f_l2e, f_l2f, f_l1a, f_l1b};
    int *function[11] = {f_l3c, f_l3d, f_l3e, f_l2a, f_l2b, f_l2c, f_l2d, f_l2e, f_l2f, f_l1a, f_l1b};

    fbt_main_loop(function, 11, input->lwe_samples, Sboxlut_clear, context); // Execute everything defined in "function"

    // lweKeySwitch(&lut_out_lwe->lwe_samples[i], key->cloud_key->bk->ks, &lut_output->lwe_samples[i]);
    for (int i = 0; i < 4; i++)
    {
        lweKeySwitch(&output->lwe_samples[i], key->cloud_key->bk->ks, &context->output[i]);
    }
}

fbt_integer *fbt_new_encrypted_2bit(int *value, int digits, LweKey *key, int n, fbt_context *context)
{
    // 定义一个fbt_integer
    fbt_integer *result = (fbt_integer *)malloc(sizeof(fbt_integer));
    result->lwe_samples = new_LweSample_array(n, key->params);
    for (int i = 0; i < n; i++)
    {
        lweSymEncrypt(&result->lwe_samples[i], modSwitchToTorus32(value[i], 8), key->params->alpha_min, key);
        // printf("%d ", modSwitchFromTorus32(lweSymDecrypt(&result->lwe_samples[i], key, 8), 8));
    }
    result->digits = digits;
    result->lwe_params = key->params;
    result->log_torus_base = context->log_torus_base;
    return result;
}

int main(int argc, char const *argv[])
{
    printf("Generating keys... This may take a few minutes... (~1m in our machine)\n");
    fflush(stdout);
    #ifdef P6_4_6_3
        TFheGateBootstrappingParameterSet *params = new_TFHE_parameters(6, 4, 6, 3);
    #else
        TFheGateBootstrappingParameterSet *params = new_TFHE_parameters(5, 5, 6, 2);
    #endif
        TFheFunctionalBootstrappingSecretKeySet *key = new_random_functional_bootstrapping_secret_keyset(params, 2);

    // FILE* secret_key = fopen("secret.key", "wb");
    // export_tfhe_functional_bootstrapping_secret_keyset_to_file(secret_key, key);
    // return 0;

    // printf("read key from file ...\n");
    // FILE *secret_key = fopen("../secret.key", "rb");
    // TFheFunctionalBootstrappingSecretKeySet *key = new_functional_bootstrapping_secret_keyset_from_file(secret_key);
    // fclose(secret_key);

    fbt_context *context = fbt_init(key->cloud_key->params, key->cloud_key->bkFFT, key->tlweKS, key->log_torus_base, 256);
    unsigned int seed;
    generate_random_bytes(8, (uint8_t *)&seed);
    srand(seed);

    int Sbox[256][4] = {0};

    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            int bin_str[4];
            HexToTwobit(SboxTable[i][j], bin_str);
            for (int k = 0; k < 4; k++)
            {
                Sbox[16 * i + j][k] = bin_str[k];
                // printf("%d ", Sbox[16*i+j][k]);
            }
            // printf("\n");
        }
    }

    int table[1024] = {0};
    for (int j = 0; j < 4; j++)
    {
        for (int i = 0; i < 256; i++)
        {
            table[256 * j + i] = Sbox[i][j];
            // printf("%d ", table[256*j+i]);
        }
    }

    int xor_result[16] = {0, 1, 2, 3, 1, 0, 3, 2, 2, 3, 0, 1, 3, 2, 1, 0};
    IntPolynomial *luts;
    int size = 16;
    int N = context->params->tgsw_params->tlwe_params->N;
    int number_of_luts = generate_polynomial_LUT(&luts, xor_result, size, context->torus_base, N);
    IntPolynomial *xorlut_clear = new_IntPolynomial_array((context->log_torus_base / log_carpov_base) * (size / context->torus_base), N);

    for (size_t j = 0; j < size / context->torus_base; j++) //
    {
        carpov_factorization(&xorlut_clear[(context->log_torus_base / log_carpov_base) * j], &luts[j], context->log_torus_base, log_carpov_base);
    }
    delete_IntPolynomial_array(number_of_luts, luts);
    
    //read Sbox
    IntPolynomial *luts2;
    int size2 = 1024;
    // int N = context->params->tgsw_params->tlwe_params->N;
    int number_of_luts2 = generate_polynomial_LUT(&luts2, table, size2, context->torus_base, N);
    IntPolynomial *Sboxlut_clear = new_IntPolynomial_array((context->log_torus_base / log_carpov_base) * (size2 / context->torus_base), N);

    for (size_t j = 0; j < size2 / context->torus_base; j++) //
    {
        carpov_factorization(&Sboxlut_clear[(context->log_torus_base / log_carpov_base) * j], &luts2[j], context->log_torus_base, log_carpov_base);
    }
    delete_IntPolynomial_array(number_of_luts2, luts2);

    //  plain: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    //  key:   01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10

    unsigned char plain[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    unsigned char SM4key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                                0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    // Compute the key expansion
    unsigned long RoundKey[32];
    sm4_setkey(RoundKey, SM4key);

    fbt_integer *X_input[36][4];

    int bin_str1[4] = {0};
    for (int i = 0; i < 36; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            X_input[i][j] = fbt_new_encrypted_2bit(bin_str1, 4, (LweKey *)key->tfhe_keys->lwe_key, 4, context);
        }
    }

    int bin_str[4];
    for (int i = 0; i < 4; i++)
    {
        // encrypt plain
        for (int j = 0; j < 4; j++)
        {
            HexToTwobit(plain[4 * i + j], bin_str);
            X_input[i][j] = fbt_new_encrypted_2bit(bin_str, 4, (LweKey *)key->tfhe_keys->lwe_key, 4, context);
        }
    }

    fbt_integer *rk[32][4];
    for (int i = 0; i < 32; i++)
    {
        unsigned char a[4];
        PUT_ULONG_BE(RoundKey[i], a, 0);
        for (int j = 0; j < 4; j++)
        {
            HexToTwobit(a[j], bin_str);
            rk[i][j] = fbt_new_encrypted_2bit(bin_str, 4, (LweKey *)key->tfhe_keys->lwe_key, 4, context);
        }
    }

    fbt_integer *result[4][4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            result[i][j] = (fbt_integer *)malloc(sizeof(fbt_integer));
            result[i][j]->lwe_samples = new_LweSample_array(2, key->tfhe_keys->lwe_key->params);
            result[i][j]->digits = 4;
            result[i][j]->lwe_params = key->tfhe_keys->lwe_key->params;
            result[i][j]->log_torus_base = context->log_torus_base;
        }
    }

    // 32 round
    clock_t begin = clock();

    for (int testtime = 0; testtime < 1; testtime++)
    {
        std::chrono::system_clock::time_point start, end;
        double AddRoundKey_totaltime = 0, LUT_totaltime = 0, Linear_totaltime = 0, Xor_totaltime = 0;
        start = std::chrono::system_clock::now();
        for (int round = 0; round < 32; round++)
        {
            printf("=================round: %d ===========\n", round);
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    lweCopy(&result[i][j]->lwe_samples[0], &X_input[round + 1][i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                    lweCopy(&result[i][j]->lwe_samples[1], &X_input[round + 2][i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                }
            }
            std::chrono::system_clock::time_point addkey_start, addkey_end;
            addkey_start = std::chrono::system_clock::now();
            // printf("============x1 + x2===========\n");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    test_2bitXOR(X_input[round + 4][i], j, result[i][j], xorlut_clear, key, context); 
                    // printf("%d ", modSwitchFromTorus32(lweSymDecrypt(&X_input[4][i]->lwe_samples[j], (LweKey *)key->tfhe_keys->lwe_key, 8), 8));
                }
            }
            // printf("\n");
            // printf("==================X1+ x2 +X3=================\n");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    lweCopy(&result[i][j]->lwe_samples[0], &X_input[round + 4][i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                    lweCopy(&result[i][j]->lwe_samples[1], &X_input[round + 3][i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    test_2bitXOR(X_input[round + 4][i], j, result[i][j], xorlut_clear, key, context); 
                    // printf("%d ", modSwitchFromTorus32(lweSymDecrypt(&X_input[4][i]->lwe_samples[j], (LweKey *)key->tfhe_keys->lwe_key, 8), 8));
                }
            }
            // printf("\n");
            // printf("==================X1+ x2 +X3 + rk[0]=================\n");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    lweCopy(&result[i][j]->lwe_samples[0], &X_input[round + 4][i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                    lweCopy(&result[i][j]->lwe_samples[1], &rk[round][i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    test_2bitXOR(X_input[round + 4][i], j, result[i][j], xorlut_clear, key, context); 
                    // printf("%d ", modSwitchFromTorus32(lweSymDecrypt(&X_input[4][i]->lwe_samples[j], (LweKey *)key->tfhe_keys->lwe_key, 8), 8));
                }
            }

            addkey_end = std::chrono::system_clock::now();
            double add_key_elapsed =
                std::chrono::duration_cast<std::chrono::milliseconds>(addkey_end - addkey_start)
                    .count();
            std::cout << " add_key one round costs: " << add_key_elapsed << "milliseconds" << std::endl;
            AddRoundKey_totaltime += add_key_elapsed;
            // printf("\n");

            //  printf("\nRunning 8-bit-to-8-bit LUT evaluation. The LUT encodes Sbox function.\n");
            std::chrono::system_clock::time_point lut_start, lut_end;
            lut_start = std::chrono::system_clock::now();
            for (int i = 0; i < 4; i++)
            {
                test_LUT_8_bit_to_8_bit(X_input[round + 4][i], X_input[round + 4][i], Sboxlut_clear, key, context);
                // fbt_integer_decrypt(X_input[round+ 4][i], (LweKey *)key->tfhe_keys->lwe_key, context);
                // printf("     ");
            }
            lut_end = std::chrono::system_clock::now();
            double lut_elapsed =
                std::chrono::duration_cast<std::chrono::milliseconds>(lut_end - lut_start)
                    .count();
            std::cout << " Sbox one round costs: " << lut_elapsed << "milliseconds" << std::endl;
            LUT_totaltime += lut_elapsed;
            // printf("\n");

            // Linear_transformation(X_input[4][i], key);
            std::chrono::system_clock::time_point Linear_start, Linear_end;

            Linear_start = std::chrono::system_clock::now();
            fbt_integer *B2[4], *B10[4], *B18[4], *B24[4];
            for (int i = 0; i < 4; i++)
            {
                B2[i] = (fbt_integer *)malloc(sizeof(fbt_integer));
                B2[i]->lwe_samples = new_LweSample_array(4, key->tfhe_keys->lwe_key->params);
                B2[i]->digits = 4;
                B2[i]->lwe_params = key->tfhe_keys->lwe_key->params;
                B2[i]->log_torus_base = context->log_torus_base;

                B10[i] = (fbt_integer *)malloc(sizeof(fbt_integer));
                B10[i]->lwe_samples = new_LweSample_array(4, key->tfhe_keys->lwe_key->params);
                B10[i]->digits = 4;
                B10[i]->lwe_params = key->tfhe_keys->lwe_key->params;
                B10[i]->log_torus_base = context->log_torus_base;

                B18[i] = (fbt_integer *)malloc(sizeof(fbt_integer));
                B18[i]->lwe_samples = new_LweSample_array(4, key->tfhe_keys->lwe_key->params);
                B18[i]->digits = 4;
                B18[i]->lwe_params = key->tfhe_keys->lwe_key->params;
                B18[i]->log_torus_base = context->log_torus_base;

                B24[i] = (fbt_integer *)malloc(sizeof(fbt_integer));
                B24[i]->lwe_samples = new_LweSample_array(4, key->tfhe_keys->lwe_key->params);
                B24[i]->digits = 4;
                B24[i]->lwe_params = key->tfhe_keys->lwe_key->params;
                B24[i]->log_torus_base = context->log_torus_base;
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    if (j == 0)
                    {
                        lweCopy(&B2[i]->lwe_samples[j], &X_input[round + 4][(i + 1) % 4]->lwe_samples[3], key->tfhe_keys->lwe_key->params);
                    }
                    else
                    {
                        lweCopy(&B2[i]->lwe_samples[j], &X_input[round + 4][i]->lwe_samples[j - 1], key->tfhe_keys->lwe_key->params);
                    }
                }
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    lweCopy(&B10[i]->lwe_samples[j], &B2[(i + 1) % 4]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                    lweCopy(&B18[i]->lwe_samples[j], &B2[(i + 2) % 4]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                    lweCopy(&B24[i]->lwe_samples[j], &X_input[round + 4][(i + 3) % 4]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                }
            }
#ifdef DEBUG
            printf("\nB2 : \n");
            for (int i = 0; i < 4; i++)
            {
                fbt_integer_decrypt(B2[i], (LweKey *)key->tfhe_keys->lwe_key, context);
                printf("     ");
            }
            printf("\nB10: \n");
            for (int i = 0; i < 4; i++)
            {
                fbt_integer_decrypt(B10[i], (LweKey *)key->tfhe_keys->lwe_key, context);
                printf("     ");
            }
            printf("\nB18: \n");
            for (int i = 0; i < 4; i++)
            {
                fbt_integer_decrypt(B18[i], (LweKey *)key->tfhe_keys->lwe_key, context);
                printf("     ");
            }
            printf("\nB24: \n");
            for (int i = 0; i < 4; i++)
            {
                fbt_integer_decrypt(B24[i], (LweKey *)key->tfhe_keys->lwe_key, context);
                printf("     ");
            }

            printf("\n");
#endif

            // printf("==================  B + B2  =================\n");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    lweCopy(&result[i][j]->lwe_samples[0], &X_input[round + 4][i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                    lweCopy(&result[i][j]->lwe_samples[1], &B2[i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    test_2bitXOR(X_input[round + 4][i], j, result[i][j], xorlut_clear, key, context);
                    // printf("%d ", modSwitchFromTorus32(lweSymDecrypt(&X_input[4][i]->lwe_samples[j], (LweKey *)key->tfhe_keys->lwe_key, 8), 8));
                }
            }

            // printf("==================  B + B2  + B10=================\n");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    lweCopy(&result[i][j]->lwe_samples[0], &X_input[round + 4][i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                    lweCopy(&result[i][j]->lwe_samples[1], &B10[i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    test_2bitXOR(X_input[round + 4][i], j, result[i][j], xorlut_clear, key, context);
                    // printf("%d ", modSwitchFromTorus32(lweSymDecrypt(&X_input[4][i]->lwe_samples[j], (LweKey *)key->tfhe_keys->lwe_key, 8), 8));
                }
            }

            // printf("==================  B + B2  +B10 + B18 =================\n");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    lweCopy(&result[i][j]->lwe_samples[0], &X_input[round + 4][i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                    lweCopy(&result[i][j]->lwe_samples[1], &B18[i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    test_2bitXOR(X_input[round + 4][i], j, result[i][j], xorlut_clear, key, context);
                    // printf("%d ", modSwitchFromTorus32(lweSymDecrypt(&X_input[4][i]->lwe_samples[j], (LweKey *)key->tfhe_keys->lwe_key, 8), 8));
                }
            }

            // printf("==================   B + B2  +B10 + B18+ B24  =================\n");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    lweCopy(&result[i][j]->lwe_samples[0], &X_input[round + 4][i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                    lweCopy(&result[i][j]->lwe_samples[1], &B24[i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                }
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    test_2bitXOR(X_input[round + 4][i], j, result[i][j], xorlut_clear, key, context);
                    // printf("%d ", modSwitchFromTorus32(lweSymDecrypt(&X_input[4][i]->lwe_samples[j], (LweKey *)key->tfhe_keys->lwe_key, 8), 8));
                }
            }
            Linear_end = std::chrono::system_clock::now();
            double Linear_elapsed =
                std::chrono::duration_cast<std::chrono::milliseconds>(Linear_end - Linear_start)
                    .count();
            std::cout << " Linear transformation one round costs: " << Linear_elapsed << "milliseconds" << std::endl;
            Linear_totaltime += Linear_elapsed;

            std::chrono::system_clock::time_point Xor_start, Xor_end;

            Xor_start = std::chrono::system_clock::now();
            // printf("==================   B + B2  + B10 + B18 + B24  + X0 =================\n");
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    lweCopy(&result[i][j]->lwe_samples[0], &X_input[round + 4][i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                    lweCopy(&result[i][j]->lwe_samples[1], &X_input[round + 0][i]->lwe_samples[j], key->tfhe_keys->lwe_key->params);
                }
            }

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    test_2bitXOR(X_input[round + 4][i], j, result[i][j], xorlut_clear, key, context);
                    // printf("%d ", modSwitchFromTorus32(lweSymDecrypt(&X_input[4][i]->lwe_samples[j], (LweKey *)key->tfhe_keys->lwe_key, 8), 8));
                }
            }
            Xor_end = std::chrono::system_clock::now();
            double Xor_elapsed =
                std::chrono::duration_cast<std::chrono::milliseconds>(Xor_end - Xor_start)
                    .count();
            std::cout << " last Xor one round costs: " << Xor_elapsed << "milliseconds" << std::endl;
            Xor_totaltime += Xor_elapsed;

            printf("result: ");
            for (int i = 0; i < 4; i++)
            {
                fbt_integer_decrypt(X_input[round + 4][i], (LweKey *)key->tfhe_keys->lwe_key, context);
                printf("     ");
            }

            printf("\n");
        }

        end = std::chrono::system_clock::now();
        double elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
                .count();

        std::cout << " AddRoundKey_totaltime costs " << AddRoundKey_totaltime << " milliseconds =  " << AddRoundKey_totaltime / 1000 << " seconds.. account for " << (AddRoundKey_totaltime / elapsed) * 100 << "%;" << std::endl;
        std::cout << " LUT_totaltime costs: " << LUT_totaltime << " milliseconds = " << LUT_totaltime / 1000 << " seconds.. account for " << (LUT_totaltime / elapsed) * 100 << "%;" << std::endl;
        std::cout << " Linear_totaltime: " << Linear_totaltime << " milliseconds = " << Linear_totaltime / 1000 << " seconds.. account for " << (Linear_totaltime / elapsed) * 100 << "%;" << std::endl;
        std::cout << " Xor_totaltime: " << Xor_totaltime << " milliseconds = " << Xor_totaltime / 1000 << " seconds.. account for " << (Xor_totaltime / elapsed) * 100 << "%;" << std::endl;
        std::cout << " homoSM4 using functional bootstrapping costs: " << elapsed << "milliseconds = " << elapsed / 1000 << " seconds.." << std::endl;
    }

    return 0;
}

// g++ homosm4-v3.cpp -O3 -std=c++11 -funroll-all-loops -march=native -I"../tfhe/src/include/" -L"../tfhe/build/libtfhe/" -ltfhe-spqlios-fma -lm -g -o homosm4-v3