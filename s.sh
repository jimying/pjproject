#!/bin/bash
BUILD_OUT=$(readlink -f $PWD/../build)
JOBS=$(nproc)
OS=$(uname -s |  tr '[:upper:]' '[:lower:]')
: ${DEBUG:=0}

case $OS in
    *bsd*)
        MAKE=gmake
        ;;
    *)
        MAKE=make
        ;;
esac

if [ $DEBUG -eq 0 ];then
    export CFLAGS="-DNDEBUG -fPIC -Wno-unused-label -Wextra -Wno-missing-field-initializers"
    INS_DIR="$BUILD_OUT/pjsip"
    echo "Build release version... install:$INS_DIR"
else
    export CFLAGS="-g -fPIC"
    INS_DIR="$BUILD_OUT/pjsip_d"
    echo "Build debug version... install:$INS_DIR"
fi

rm -rf $INS_DIR
$MAKE distclean
./configure --prefix=$INS_DIR \
    --enable-epoll \
    --disable-libuuid \
    --disable-gsm-codec \
    --disable-speex-codec --disable-speex-aec \
    --disable-l16-codec \
    --disable-g722-codec \
    --disable-g7221-codec \
    --disable-ilbc-codec \
    --disable-bcg729 \
    --disable-silk \
    --disable-video \
    --disable-libwebrtc \
    --disable-sound \
    --disable-opus \
    --disable-ssl \
    --disable-upnp \
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
