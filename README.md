## Dependencies

### Ubuntu/Debian
sudo apt install cmake build-essential qt6-base-dev libssl-dev
# liboqs — build from source
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc) && sudo make install && sudo ldconfig

### Fedora
sudo dnf install cmake gcc-c++ qt6-qtbase-devel openssl-devel
# liboqs — same as above

### macOS
brew install cmake qt openssl
# liboqs — same as above

## Build
mkdir build && cd build
cmake ..
make