
cd src/jitike-protobuf &&
make all &&
make install &&
cd ../.. &&
./autogen.sh &&
./configure --enable-socket-vpp --enable-libipsec --enable-kernel-vpp --enable-jitsec \
            --sysconfdir=/etc --with-piddir=/etc/ipsec.d/run \
            --disable-kernel-netlink --disable-socket-default --enable-dhcp &&
make &&
sudo make install
