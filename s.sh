#!/bin/bash
BUILD_OUT=$PWD/../build
JOBS=8
OS=$(uname -s |  tr '[:upper:]' '[:lower:]')

case $OS in
    *bsd*)
        MAKE=gmake
        ;;
    *)
        MAKE=make
        ;;
esac

#export CFLAGS="-g"
export CFLAGS="-DNDEBUG -fPIC"
$MAKE distclean
./configure --prefix=$BUILD_OUT/pjsip \
    --enable-epoll \
    --disable-libuuid \
    --disable-gsm-codec \
    --disable-speex-codec --disable-speex-aec \
    --disable-l16-codec \
    --disable-g722-codec \
    --disable-g7221-codec \
    --disable-ilbc-codec \
    --disable-video \
    --disable-libwebrtc \
    --disable-sound \
    --disable-opus \
    --disable-ssl \
    --disable-libsrtp
    #--with-opus=$BUILD_OUT/opus

rm -f pjlib/include/pj/config_site.h
cp -f config_site.h pjlib/include/pj
$MAKE dep
#$MAKE -C pjlib/build -j  $JOBS
#$MAKE -C pjlib-util/build -j  $JOBS
#$MAKE -C pjnath/build -j  $JOBS
$MAKE -j $JOBS
$MAKE install
