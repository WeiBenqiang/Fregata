#include <cassert>
#include <chrono>
#include <iostream>
#include <random>
#include <tfhe++.hpp>

using namespace std;

int main()
{
        
    std::random_device seed_gen;
    std::default_random_engine engine(seed_gen());
    std::uniform_int_distribution<uint32_t> binary(0, 1);

    // Generate key
    // TFHEpp::SecretKey *sk = new TFHEpp::SecretKey;
    // TFHEpp::EvalKey ek;
    // ek.emplaceiksk<iksP>(*sk);
    // ek.emplacebkfft<bkP>(*sk);
    // ek.emplaceprivksk4cb<privksP>(*sk);

    cout << "------ Key Generation ------" << endl;
    TFHEpp::SecretKey *sk = new TFHEpp::SecretKey;
    TFHEpp::EvalKey ek;

    ek.emplaceiksk<TFHEpp::lvl10param>(*sk);    // used for ks 
    ek.emplacebkfft<TFHEpp::lvl01param>(*sk);   // used for identitybootstrapping

    std::vector<TFHEpp::TLWE<TFHEpp::lvl0param>> cones(10);

    TFHEpp::lvl0param::T pones[10]= {0,1,1,0,1,0,1,1,1,0}; 

    std::cout <<" enc start " << std::endl;

    // typename TFHEpp::lvl0param::T pones; 
    for (int i = 0; i < 10; i++)
    {
        cones[i] = TFHEpp::tlweSymIntEncrypt<TFHEpp::lvl0param>(pones[i], TFHEpp::lvl0param::alpha,
                                                                               sk->key.get<TFHEpp::lvl0param>());
    }
    std::cout<< "cones 解密看看" <<endl;

    for (int i = 0; i < 10; i++)
    {
        typename TFHEpp::lvl0param::T res_plain = TFHEpp::tlweSymIntDecrypt<TFHEpp::lvl0param>(cones[i], sk->key.get<TFHEpp::lvl0param>());
        std::cout << res_plain << " " ;

    }
    std::cout << std::endl;

    std::cout <<" enc end  " << std::endl;
    std::vector<TFHEpp::TLWE<TFHEpp::lvl0param>> res(10);
    
    std:;cout << "start to id boot " << std::endl;
    for (int i = 0; i < 10; i++)
    {
        TFHEpp::IdentityBootstrapping(res[i], cones[i], ek);
    }
    

    std::cout<< "解密看看" <<endl;

    for (int i = 0; i < 10; i++)
    {
        typename TFHEpp::lvl0param::T res_plain = TFHEpp::tlweSymIntDecrypt<TFHEpp::lvl0param>(res[i], sk->key.get<TFHEpp::lvl0param>());
        std::cout << res_plain << " " ;

    }
    std::cout << std::endl;
    


    return 0;
}
