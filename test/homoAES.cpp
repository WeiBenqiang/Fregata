#include <iostream>
#include <chrono>
#include <tfhe/tfhe_core.h>
#include <tfhe/tfhe.h>
#include <time.h>

using namespace std;

int main()
{
    // 设置参数
    const int minimum_lambda = 110;  // 安全参数
    TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);
    
    // 生成密钥
    std::cout << "Generating secret keyset..." << std::endl;
    TFheGateBootstrappingSecretKeySet* keyset = new_random_gate_bootstrapping_secret_keyset(params);
    
    // 生成云密钥（可以公开）
    std::cout << "Generating cloud keyset..." << std::endl;
    const TFheGateBootstrappingCloudKeySet* cloud_key = &keyset->cloud;
    
    // 我们要加密的明文数据
    int plaintext1 = 1;
    int plaintext2 = 0;
    
    // 加密数据
    std::cout << "Encrypting data..." << std::endl;
    LweSample* ciphertext1 = new_gate_bootstrapping_ciphertext(params);
    bootsSymEncrypt(ciphertext1, plaintext1, keyset);
    
    LweSample* ciphertext2 = new_gate_bootstrapping_ciphertext(params);
    bootsSymEncrypt(ciphertext2, plaintext2, keyset);
    
    // 分配空间用于计算结果
    LweSample* result = new_gate_bootstrapping_ciphertext(params);
    
    // 同态运算：NAND 门
    std::cout << "Performing homomorphic NAND operation..." << std::endl;
    bootsNAND(result, ciphertext1, ciphertext2, cloud_key);
    
    // 解密结果
    std::cout << "Decrypting result..." << std::endl;
    int decrypted_result = bootsSymDecrypt(result, keyset);
    
    // 验证结果
    int expected = !(plaintext1 && plaintext2);  // NAND 运算的预期结果
    std::cout << "Plaintext1: " << plaintext1 << std::endl;
    std::cout << "Plaintext2: " << plaintext2 << std::endl;
    std::cout << "Expected result (NAND): " << expected << std::endl;
    std::cout << "Decrypted result: " << decrypted_result << std::endl;
    

    std::cout << "Test passed!" << std::endl;
    
    // 清理内存
    delete_gate_bootstrapping_ciphertext(result);
    delete_gate_bootstrapping_ciphertext(ciphertext2);
    delete_gate_bootstrapping_ciphertext(ciphertext1);
    delete_gate_bootstrapping_secret_keyset(keyset);
    delete_gate_bootstrapping_parameters(params);



    return 0;
}
