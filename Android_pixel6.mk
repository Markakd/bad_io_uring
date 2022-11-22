LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	exp_pixel6.c

LOCAL_MODULE := exp
LOCAL_LDFLAGS   += 
LOCAL_CFLAGS    += -O0

include $(BUILD_EXECUTABLE)


