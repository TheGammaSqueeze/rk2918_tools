CC=gcc
CFLAGS := -g -O3 -DUSE_OPENSSL -Wall -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
LDLIBS := -lssl -lcrypto

#CFLAGS := -DUSE_GCRYPT
#LDLIBS := -lgcrypt

TARGETS := afptool img_unpack img_maker mkkrnlimg

all: ${TARGETS}

clean:
	rm -f ${TARGETS}
