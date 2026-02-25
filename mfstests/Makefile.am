TESTS = mfstest_datapack mfstest_clocks mfstest_crc32 mfstest_bitops mfstest_delayrun

AM_CPPFLAGS = -I$(top_srcdir)/mfscommon

noinst_PROGRAMS = $(TESTS) mfsbench_hotpath mfsbench_io

mfstest_datapack_SOURCES = \
	mfstest_datapack.c mfstest.h \
	../mfscommon/datapack.h

mfstest_datapack_CFLAGS =

mfstest_clocks_SOURCES = \
	mfstest_clocks.c mfstest.h \
	../mfscommon/portable.h \
	../mfscommon/clocks.h ../mfscommon/clocks.c

mfstest_clocks_CFLAGS =

mfstest_crc32_SOURCES = \
	mfstest_crc32.c mfstest.h \
	../mfscommon/crc.h ../mfscommon/crc.c \
	../mfscommon/crc_pclmul.c ../mfscommon/crc_pclmul.h \
	../mfscommon/clocks.h ../mfscommon/clocks.c

mfstest_crc32_CFLAGS = $(PCLMUL_CFLAGS)

mfstest_bitops_SOURCES = \
	mfstest_bitops.c mfstest.h \
	../mfscommon/bitops.h \
	../mfscommon/clocks.h ../mfscommon/clocks.c

mfstest_bitops_CFLAGS =

mfstest_delayrun_SOURCES = \
	mfstest_delayrun.c mfstest.h \
	../mfscommon/portable.h \
	../mfscommon/delayrun.h ../mfscommon/delayrun.c \
	../mfscommon/mfslog.h ../mfscommon/mfslog.c \
	../mfscommon/clocks.h ../mfscommon/clocks.c \
	../mfscommon/strerr.h ../mfscommon/strerr.c

mfstest_delayrun_LDADD = $(PTHREAD_LIBS)
mfstest_delayrun_CFLAGS = $(PTHREAD_CFLAGS) -D_USE_PTHREADS
mfstest_delayrun_CPPFLAGS = $(PTHREAD_CPPFLAGS) -I$(top_srcdir)/mfscommon

mfsbench_hotpath_SOURCES = \
	mfsbench_hotpath.c \
	../mfscommon/crc.h ../mfscommon/crc.c \
	../mfscommon/crc_pclmul.c ../mfscommon/crc_pclmul.h \
	../mfscommon/clocks.h ../mfscommon/clocks.c \
	../mfscommon/random.h ../mfscommon/random.c \
	../mfscommon/pcqueue.h ../mfscommon/pcqueue.c \
	../mfscommon/mfslog.h ../mfscommon/mfslog.c \
	../mfscommon/strerr.h ../mfscommon/strerr.c

mfsbench_hotpath_LDADD = $(PTHREAD_LIBS) -lm
mfsbench_hotpath_CFLAGS = $(PTHREAD_CFLAGS) $(PCLMUL_CFLAGS) -D_USE_PTHREADS
mfsbench_hotpath_CPPFLAGS = $(PTHREAD_CPPFLAGS) -I$(top_srcdir)/mfscommon

mfsbench_io_SOURCES = \
	mfsbench_io.c \
	../mfscommon/clocks.h ../mfscommon/clocks.c

mfsbench_io_LDADD = $(PTHREAD_LIBS) ../mfsclient/libmfsio.la
mfsbench_io_CFLAGS = $(PTHREAD_CFLAGS) -D_USE_PTHREADS
mfsbench_io_CPPFLAGS = $(PTHREAD_CPPFLAGS) -I$(top_srcdir)/mfscommon -I$(top_srcdir)/mfsclient

distclean-local: distclean-am
	-rm -rf ./$(DEPDIR)
	-rm -f Makefile
