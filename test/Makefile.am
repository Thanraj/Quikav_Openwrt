FILES = quik.cab quik.exe quik.zip \
	quik.arj quik.exe.rtf quik.exe.szdd quik.tar.gz quik.chm quik.sis \
	quik-aspack.exe quik-pespin.exe quik-upx.exe quik-fsg.exe quik-mew.exe\
	quik-nsis.exe quik-petite.exe quik-upack.exe quik-wwpack.exe quik.pdf\
	quik.mail quik.ppt quik.tnef quik.ea05.exe quik.ea06.exe quik.d64.zip\
	quik.exe.mbox.base64 quik.exe.mbox.uu quik.exe.binhex quik.ole.doc \
	quik.impl.zip quik.exe.html quik.bin-be.cpio quik.bin-le.cpio \
	quik.newc.cpio quik.odc.cpio quik-yc.exe quik_IScab_int.exe \
	quik_IScab_ext.exe quik_ISmsi_int.exe quik_ISmsi_ext.exe quik.7z \
	quik_cache_emax.tgz quik.iso quikjol.iso

if ENABLE_UNRAR
FILES += quik-v2.rar quik-v3.rar
endif

if HAVE_LIBBZ2
FILES += quik.exe.bz2 quik.bz2.zip
endif

if HAVE_LIBXML2
#placeholder
endif

SPLIT_DIR=$(top_srcdir)/test/.split

all: $(FILES)

$(FILES) :
	cat $(SPLIT_DIR)/split.$@aa $(SPLIT_DIR)/split.$@ab > $@

clean-local:
	rm -f quik*

EXTRA_DIST = .split

check: all
