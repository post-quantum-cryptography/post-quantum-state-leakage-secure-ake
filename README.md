# Signal Conforming AKE protocol

## Description
Repository provides a full-fledged, generic C implementation of our (weakly deniable) protocol. Implementation instantiates a protocol with several Round 3 candidates (finalists and alternates) to the NIST post-quantum standardization process. Benchmarking tool can be use to compare the resulting bandwidth and computation costs.

## Building

Project uses [PQ Crypto Catalog](https://github.com/henrydcase/pqc), [LibTomCrypt](https://github.com/libtom/libtomcrypt) as cryptographic primitives providers. We also use branch of ``google-benchmark`` for benchmarking. Those libraries are added as git submodules. We tested compilation on Linux platform only.

Use the following commands for building:

* Checkout & Build:
```
git clone https://github.com/post-quantum-cryptography/post-quantum-state-leakage-secure-ake.git
cd post-quantum-state-leakage-secure-ake
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

## Results

Compilation produces two binaries - ``sneik_test`` and ``sneik_bench``. The former runs a set of tests, which checks if two parties can use the protocol to establish a session. The latter produces measurement results described in chapter 5 of the paper. File [``etc/results.xls``](https://github.com/post-quantum-cryptography/post-quantum-state-leakage-secure-ake/blob/main/etc/results.xls) stores those results.
