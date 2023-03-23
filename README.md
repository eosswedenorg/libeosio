![](https://github.com/eosswedenorg/libeosio/workflows/CI/badge.svg)
[![GitHub release](https://img.shields.io/github/v/release/eosswedenorg/libeosio?include_prereleases)](https://github.com/eosswedenorg/libeosio/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# libeosio

Independent C++ library for [EOS](https://eos.io/)

NOTE: This repository has no connection to the official EOS code.

## Compiling the library

You will need `openssl` development files (version 1.1 or later) to compile and `cmake 3.15` or later to compile this project.

### Elliptic curve backend

There is two different backend implementation for the elliptic curve part of the library:

* `OpenSSL` as mentioned before. however you still need to link to openssl even if it is not used as the EC backend
  because more of the codebase uses it.

* `libsecp256k1`

Default is to use `libsecp256k1` as it is more optimized.

You can switch implementation by modifing the cmake variable `EC_LIB`.

### CMake

You can install `cmake` by reading the [official guide](https://cmake.org/install).

### Linux

**NOTE:** Only Ubuntu `20.04` and `22.04` is officially supported.

The project should compile fine on most versions/distros but it is only tested
and distributed for Ubuntu `20.04` and `22.04` by [Sw/eden](https://www.eossweden.org).

#### Dependencies

**Ubuntu (or other debian based distros)**

First you need to have a compiler, `openssl` and `cmake`. this can be installed with apt.

```sh
$ apt-get install gcc g++ cmake libssl-dev
```
If you need a newer version of cmake then apt provides.
Checkout the official [CMake APT repository](https://apt.kitware.com/).

**Other**

Consult your package manager's manual for getting `openssl`,`g++` and `cmake` installed.

If you need a newer version of cmake then your package manager provides. checkout the [official guide](https://cmake.org/install).

### MacOS

#### Dependencies

You must have a compiler installed. This project is known to build with `Xcode 11.0` but other versions should work.

You need to have openssl and cmake installed also, this can be done with this `brew` command:
```sh
$ brew install openssl cmake
```

If you need a newer version of cmake then brew provides. checkout the [official guide](https://cmake.org/install)

#### Build

```sh
$ mkdir build && cd build
$ cmake .. && make
```

**MacOS:** You may need to point `cmake` to `openssl` by passing the argument
`-D OPENSSL_ROOT_DIR=/usr/local/opt/openssl@1.1` if openssl is not under `/usr/local/opt/openssl@1.1` you need to find the correct path.

### Windows

#### Dependencies

First you will need a compiler.

[Build Tools for Visual Studio 2019](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=BuildTools&rel=16) (Selecting C++ during installation) is recommended.

By default `cmake` will use the bundled openssl package located at `vendor/openssl-1.1.1e-win-static.zip`

If you like to use an other version of OpenSSL then the static one bundled with this repo
you need to set `OPENSSL_ROOT_DIR` to the directory where OpenSSL is located on the system.

For example:

```
C:\repo> cmake -D OPENSSL_ROOT_DIR=C:/path/to/openssl -B build
```

**NOTE:** `cmake` uses forward slash `/` for path even for windows. so make sure you use that when setting `OPENSSL_ROOT_DIR`

#### Build.

Run cmake

```
C:\repo> cmake -B build
C:\repo> cmake --build build --config Release
```

## Security notice

Elliptic curve crypthographic operations is done using either `OpenSSL` or `libsecp256k1` libraries.
This library (libeosio) will never expose sensitve cryptographic information
to anything but the computers memory.
You are free to inspect the source code and compile yourself to verify.

However, use this at your own risk. we cannot guarantee that the keys are
cryptographically secure as this depends on the elliptic curve
implementation (alto both OpenSSL and libsecp256k1 are widely used and should be safe)

Please read the `LICENSE` file.

```
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## Author

Henrik Hautakoski - [henrik@eossweden.org](mailto:henrik@eossweden.org)
