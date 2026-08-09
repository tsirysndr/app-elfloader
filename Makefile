WITH_LWIP       ?= y
WITH_MUSL       ?= n
WITH_NEWLIB     ?= n

UK_ROOT  ?= $(PWD)/workdir/unikraft
UK_LIBS  ?= $(PWD)/workdir/libs
UK_BUILD ?= $(PWD)/workdir/build
UK_PLATS ?= $(PWD)/workdir/plats

# No libelf: the loader parses ELF itself (see rust/src/elf.rs).
LIBS-y                  :=
LIBS-$(WITH_LWIP)       := $(LIBS-y):$(UK_LIBS)/lwip
LIBS-$(WITH_MUSL)       := $(LIBS-y):$(UK_LIBS)/musl
LIBS-$(WITH_NEWLIB)     := $(LIBS-y):$(UK_LIBS)/newlib
PLATS-y                 :=

all:
	@$(MAKE) -C $(UK_ROOT) A=$(PWD) L=$(LIBS-y) O=$(UK_BUILD) P=$(PLATS-y)

# Loader unit tests, on the host. No Unikraft tree needed.
.PHONY: test
test:
	@cargo test --manifest-path $(PWD)/rust/Cargo.toml

$(MAKECMDGOALS):
	@$(MAKE) -C $(UK_ROOT) A=$(PWD) L=$(LIBS-y) O=$(UK_BUILD) P=$(PLATS-y) $(MAKECMDGOALS)
