#!/bin/bash
#
# Compile test script (parallel limited to 2 jobs for stability)

JOBS=2

rm cpuminer cpuminer-m2 cpuminer-m4 cpuminer-armv9-crypto-sha3 cpuminer-armv9-crypto cpuminer-armv9 \
cpuminer-armv8.5-crypto-sha3-sve2 cpuminer-armv8.4-crypto-sha3 cpuminer-armv8 cpuminer-armv8-crypto > /dev/null 2>&1

make distclean || echo clean
rm -f config.status
./autogen.sh || echo done

CFLAGS="-O3 -march=armv9-a+crypto+sha3 -Wall -flax-vector-conversions" ./configure --with-curl
make -j$JOBS
mv cpuminer cpuminer-armv9-crypto-sha3

make clean || echo clean
CFLAGS="-O3 -march=armv9-a+crypto -Wall -flax-vector-conversions" ./configure --with-curl
make -j$JOBS
mv cpuminer cpuminer-armv9-crypto

make clean || echo clean
CFLAGS="-O3 -march=armv9-a -Wall -flax-vector-conversions" ./configure --with-curl
make -j$JOBS
mv cpuminer cpuminer-armv9

make clean || echo clean
CFLAGS="-O3 -march=armv9.2-a+crypto+sha3 -Wall -flax-vector-conversions" ./configure --with-curl
make -j$JOBS
mv cpuminer cpuminer-m4

make clean || echo clean
CFLAGS="-O3 -march=armv8.6-a+crypto+sha3 -Wall -flax-vector-conversions" ./configure --with-curl
make -j$JOBS
mv cpuminer cpuminer-m2

make clean || echo clean
CFLAGS="-O3 -march=armv8.5-a+crypto+sha3+sve2 -Wall -flax-vector-conversions" ./configure --with-curl
make -j$JOBS
mv cpuminer cpuminer-armv8.5-crypto-sha3-sve2

make clean || echo clean
CFLAGS="-O3 -march=armv8.4-a+crypto+sha3 -Wall -flax-vector-conversions" ./configure --with-curl
make -j$JOBS
mv cpuminer cpuminer-armv8.4-crypto-sha3

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=armv8.2-a+crypto -Wall -flax-vector-conversions" ./configure --with-curl
make -j$JOBS
mv cpuminer cpuminer-armv8-crypto

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=armv8-a+crypto -Wall -flax-vector-conversions" ./configure --with-curl
make -j$JOBS
mv cpuminer cpuminer-armv8-crypto

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=armv8-a -Wall -flax-vector-conversions" ./configure --with-curl
make -j$JOBS
mv cpuminer cpuminer-armv8

make clean || echo clean
rm -f config.status
CFLAGS="-O3 -march=native -Wall -flax-vector-conversions" ./configure --with-curl
make -j$JOBS
