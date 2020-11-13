# Signal Conforming AKE protocol

## Description
Repository provides a full-fledged, generic C implementation of our (weakly deniable) protocol. Implementation instantiates a protocol with several Round 3 candidates (finalists and alternates) to the NIST post-quantum standardization process. Benchmarking tool can be use to compare the resulting bandwidth and computation costs.

## Building

Project uses ``open-quantum-safe``, ``LibTomCrypt`` as cryptographic primitives providers. We also use branch of ``google-benchmark`` for benchmarking. Those libraries are added as git submodules. On Linux platform code can be built in following way:

* Checkout:
```
git clone git@github.com:post-quantum-cryptography/post-quantum-state-leakage-secure-ake.git
cd post-quantum-state-leakage-secure-ake
git submodule init
git submodule update
```

* Build:

```
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

## Results

We provide number of most interesting results in the paper. All the results can be found in the ``etc/results.xls`` file.
