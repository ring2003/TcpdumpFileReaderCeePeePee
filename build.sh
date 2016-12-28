#!/bin/bash
mkdir 3rd &> /dev/null
cd 3rd
git clone https://github.com/seladb/PcapPlusPlus.git
cd PcapPlusPlus
./configure-linux.sh <<EOF
no
no
EOF
make all
cd ../../ && mkdir build
cd build && cmake ..
make && make install
