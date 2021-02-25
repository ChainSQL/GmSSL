#
# crypto/gmalg/Makefile
#

DIR=	gmalg
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g -Wall
MAKEFILE=	Makefile
OBJCOPY=    objcopy --localize-hidden
LD=     ld -r
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIBCRYPTOBJ= ../gmalg/lib$(DIR).o
LIBFINAL_CRYPTOBJ= $(TOP)/libcrypto.o
LIB= $(TOP)/libcrypto.a
LIBSRC=	gmalg.cpp
LIBOBJ=	gmalg.o

SRC= $(LIBSRC)

EXHEADER= gmalg.h
HEADER=	 $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	# @$(foreach var,$(LIBOBJ),\
    #     $(OBJCOPY) $(var) $(var);)
	# $(AR) $(LIB) $(LIBOBJ)
	# $(RANLIB) $(LIB) || echo Never mind.
	# $(LD) $(LIBOBJ) -o $(LIBCRYPTOBJ)
	@touch lib

gmalg.o:
	gcc -I.. -I../.. -I../../include  -DOPENSSL_THREADS -D_REENTRANT -fvisibility=hidden -DDSO_DLFCN -DHAVE_DLFCN_H -fPIC -m64 -DL_ENDIAN -O3 -Wall -DOPENSSL_IA32_SSE2 -DOPENSSL_BN_ASM_MONT -DOPENSSL_BN_ASM_MONT5 -DOPENSSL_BN_ASM_GF2m -DSHA1_ASM -DSHA256_ASM -DSHA512_ASM -DMD5_ASM -DAES_ASM -DVPAES_ASM -DBSAES_ASM -DWHIRLPOOL_ASM -DGHASH_ASM -DECP_NISTZ256_ASM   -c -o gmalg.o gmalg.cpp

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

gmalg.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
gmalg.o: ../../include/openssl/sms4.h gmalg.cpp