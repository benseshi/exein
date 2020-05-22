BRH=newmakefile
VER=v0.6-17
GITVER=NONE
GITBRH=NONE
# ----------- commands
CC=gcc
AR=ar
RM=rm
MD=mkdir
SED=sed
GIT=git
TOUCH=touch
# ----------- Directories
IDIR =./include
ODIR=./build
LDIR=./lib
BIN=./bin
# ----------- Flags
LIBS=-lexnl
CFLAGS=-I$(IDIR) -L$(LDIR) -pthread
DEBUGSYM=-g
# ----------- sources
LIBNAME=libexnl
AUXALLOCATOR=libmealloc
DEBUG=$(shell which $(GIT))

ifneq (, $(shell which $(GIT)))
 GITVER = $(shell $(GIT) describe --tags --broken --dirty 2> /dev/null || echo NONE)
 GITVERSHORT =$(shell echo $(GITVER) | $(SED) -e 's/\-g.*//')
 GITBRH = $(shell $(GIT) rev-parse --abbrev-ref HEAD 2> /dev/null || echo NONE)
endif

ifneq ($(GITVER), NONE)
 ifneq ($(GITVERSHORT), $(VER))
  $(shell $(TOUCH) -r Makefile /tmp/Makefile.tmp)
  $(shell $(SED) -i 's|^BRH=.*|BRH='$(GITBRH)'|' Makefile)
  $(shell $(SED) -i 's|^VER=.*|VER='$(GITVERSHORT)'|' Makefile)
  $(info Script vars updated  )
 endif
 VER=$(GITVER)
endif

ifneq ($(GITBRH), NONE)
 BRH=$(GITBRH)
endif

VERNUM = $(shell echo "$(VER) ($(BRH))")

HDR=include/libexnl.h include/libmealloc.h include/uthash.h
SRC=signal.c $(LIBNAME).c $(AUXALLOCATOR).c
OBJ=$(SRC:%.c=$(ODIR)/%.o)

SHAREDLIB=$(LDIR)/$(LIBNAME).so
STATICLIB=$(LDIR)/$(LIBNAME).a

VERSION_STRING=$(LIBNAME)_$(VERNUM)

all: $(SHAREDLIB) $(STATICLIB)

$(ODIR):
	$(MD) -p $(ODIR)

$(LDIR):
	$(MD) -p $(LDIR)

$(ODIR)/%.o: %.c $(HDR) $(ODIR) Makefile
	$(CC) $(DEBUGSYM) $(CFLAGS) -fPIC -c -DVERSION_STRING='"$(VERSION_STRING)"' -o $@ $<

$(SHAREDLIB): $(LDIR) $(OBJ)
	$(CC) -shared $(CFLAGS) $(OBJ) -o $@
	@echo "just built $(VERSION_STRING)"
	@$(TOUCH) -r /tmp/Makefile.tmp Makefile

$(STATICLIB): $(LDIR) $(OBJ)
	$(AR) rcs $@ $(OBJ)
	@$(TOUCH) -r /tmp/Makefile.tmp Makefile

samples: examples/testexnl.c examples/block.c
	mkdir -p bin
	$(CC) $(DEBUGSYM) -o $(BIN)/testexnl examples/testexnl.c $(CFLAGS) $(LIBS)
	$(CC) $(DEBUGSYM) -o $(BIN)/block examples/block.c $(CFLAGS) $(LIBS)
	@$(TOUCH) -r /tmp/Makefile.tmp Makefile

samples-static: examples/testexnl.c examples/block.c
	mkdir -p bin
	$(CC) -static $(DEBUGSYM) -o $(BIN)/testexnl examples/testexnl.c $(CFLAGS) $(LIBS)
	$(CC) -static $(DEBUGSYM) -o $(BIN)/block examples/block.c $(CFLAGS) $(LIBS)
	@$(TOUCH) -r /tmp/Makefile.tmp Makefile

.PHONY: clean

clean:
	$(RM) -rf $(ODIR) $(BIN) $(LDIR)
	$(RM) -f $(TEST)
	@$(TOUCH) -r /tmp/Makefile.tmp Makefile
