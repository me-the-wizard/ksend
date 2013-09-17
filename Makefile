default: all
.PHONY: default force all modules clean
force: ;

all: modules

.SUFFIXES:
SHELL := /bin/bash
Q := @

ifndef M
   M=$(CURDIR)
endif


os_ver := $(shell uname -r)
mod_build_dir := /lib/modules/$(os_ver)/build


obj-m += test_send.o


modules clean: force
	$(Q)$(MAKE) -C $(mod_build_dir) M=$(M) $@

