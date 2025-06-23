# Root Makefile for all payloads

# Find all subdirectories containing a Makefile
SUBDIRS := $(shell find . -mindepth 1 -maxdepth 1 -type d -exec test -f '{}/Makefile' \; -print | sed 's|^\./||')

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	@$(foreach dir,$(SUBDIRS),$(MAKE) -C $(dir) clean;)
