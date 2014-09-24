#!/bin/sh

export PATH=/home/olaf/ee/red-brick/image/tools/gcc-linaro-arm-linux-gnueabihf-4.8-2013.10_linux/bin:$PATH
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf-
