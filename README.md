# Signal Conforming AKE protocol

## Building

Project uses ``open-quantum-safe``, ``LibTomCrypt`` as cryptographic primitives providers. We also use branch of ``google-benchmark`` for benchmarking. Those libraries are added as git submodules.

To initialize submodules (must be executed only once:

```
git submodule init
git submodule update
```

``cmake`` must be used to build the project:

```
mkdir -p build
cd build
cmake ..
make
```

