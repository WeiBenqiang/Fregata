# Homomorphic evalution of SM4 and AES based TFHE sheme.

This repository achieves faster homomorphic  evalution of SM4 and AES based on [TFHE](https://eprint.iacr.org/2018/421.pdf) scheme.

To use this repository, you should install [TFHE](https://github/tfhe/tfhe) library firstly.
To run this repository, clone the repo and type :
```
cd Faster-homoSM4andAES
```

* GBSmode:  cd GBSmode;mkdir build; cd build;cmake ..; make
* FBSmode: cd FBSmode;mkdir build; cd build;cmake ..; make
* CBSmode: cd CBSmode;mkdir build; cd build;cmake -DENABLE_TEST=ON ..; make; cd homoSM4_CB
