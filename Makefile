TARGETS := qasm2 libqasm2.a libqasm2.so
SRCS_C := rpn_calc.c diskstorage.c strtoint32_ex.c error_fl.c
SRCS_MAIN_C := qasm2.c
SRCS_L := qasm2_anal.l
CFLAGS := -Wall -Wextra -pedantic -O2 -g -pipe
ARFLAGS := cr
CC := gcc
LEX := lex
AR := ar
RANLIB := ranlib
RM := rm -f
CTAGS := ctags

all:

SRCS_L_C := $(SRCS_L:%.l=%.l.c)
SRCS := $(SRCS_C) $(SRCS_MAIN_C) $(SRCS_L_C)
SRCS_WITHOUT_MAIN := $(SRCS_C) $(SRCS_L_C)
OBJS := $(SRCS:%.c=%.c.o)
OBJS_WITHOUT_MAIN := $(SRCS_WITHOUT_MAIN:%.c=%.c.o)
DEPS := $(SRCS:%.c=%.c.d)
ALLDEPS = $(MAKEFILE_LIST_SANS_DEPS)

.PRECIOUS: $(SRCS_L_C)
.DELETE_ON_ERROR: $(SRCS_L_C)
.DELETE_ON_ERROR: $(DEPS)

VALID_MAKECMDGOALS := all $(TARGETS) %.c.o %.c.d %.l.c clean tags
NONEED_DEP_MAKECMDGOALS := clean tags

EXTRA_MAKECMDGOALS := $(filter-out $(VALID_MAKECMDGOALS), $(MAKECMDGOALS))
ifneq '$(EXTRA_MAKECMDGOALS)' ''
  $(error No rule to make target `$(word 1, $(EXTRA_MAKECMDGOALS))')
else
  ifeq '$(filter-out $(NONEED_DEP_MAKECMDGOALS), $(MAKECMDGOALS))' '$(MAKECMDGOALS)'
    sinclude $(DEPS)
	else
    ifneq '$(words $(MAKECMDGOALS))' '1'
      $(error Specify only one target if you want to make target which needs no source code dependency)
    endif
  endif
endif

MAKEFILE_LIST_SANS_DEPS := $(filter-out %.c.d, $(MAKEFILE_LIST))

LINK.o = $(CC) $(LDFLAGS) $(EXTRALDFLAGS) $(TARGET_ARCH)
COMPILE.o = $(CC) $(CFLAGS) $(EXTRACFLAGS) $(CPPFLAGS) $(EXTRACPPFLAGS) $(TARGET_ARCH) -shared
COMPILE.c = $(CC) $(CFLAGS) $(EXTRACFLAGS) $(CPPFLAGS) $(EXTRACPPFLAGS) $(TARGET_ARCH) -fPIC -c
MKDEP.c = $(CC) $(CFLAGS) $(EXTRACFLAGS) $(CPPFLAGS) $(EXTRACPPFLAGS) $(TARGET_ARCH) -M -MP -MT $<.o -MF $@
LEX.l = $(LEX) $(LFLAGS) $(EXTRALFLAGS) -t

all: $(TARGETS)

qasm2: $(OBJS) $(ALLDEPS)
	$(LINK.o) $(OUTPUT_OPTION) $(OBJS) $(LOADLIBES) $(LDLIBS)

%.a:
libqasm2.a: $(OBJS_WITHOUT_MAIN) $(ALLDEPS)
	$(AR) $(ARFLAGS) $@ $(OBJS_WITHOUT_MAIN)
	$(RANLIB) $@

%.so:
libqasm2.so: $(OBJS_WITHOUT_MAIN) $(ALLDEPS)
	$(COMPILE.o) $(OUTPUT_OPTION) $(OBJS_WITHOUT_MAIN) $(LOADLIBES) $(LDLIBS)

%.o:
%.c.o: %.c $(ALLDEPS)
	$(COMPILE.c) $(OUTPUT_OPTION) $<

%.d:
%.c.d: %.c $(ALLDEPS)
	$(MKDEP.c) $<

%.c:
%.l.c: %.l $(ALLDEPS)
	$(RM) $@
	$(LEX.l) $< >$@

%.l:

.PHONY: clean
clean:
	$(RM) tags
	$(RM) $(TARGETS)
	$(RM) $(OBJS)
	$(RM) $(DEPS)
	$(RM) $(SRCS_L_C)

tags: $(SRCS_C) $(SRCS_MAIN_C) $(SRCS_L)
	$(CTAGS) $^
