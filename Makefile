
# ARCH := $(shell adb shell getprop ro.product.cpu.abi)
# SDK_VERSION := $(shell adb shell getprop ro.build.version.sdk)

ARCH := arm64-v8a
SDK_VERSION := android-30

all: pixel

android_build:
	ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk APP_ABI=$(ARCH) APP_PLATFORM=$(SDK_VERSION)

pixel:
	ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android_pixel6.mk APP_ABI=$(ARCH) APP_PLATFORM=$(SDK_VERSION)
	cp libs/arm64-v8a/exp ./exp

s22:
	ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android_s22.mk APP_ABI=$(ARCH) APP_PLATFORM=$(SDK_VERSION)
	cp libs/arm64-v8a/exp ./exp

clean:
	rm -rf libs
	rm -rf obj

