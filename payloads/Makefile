# Root Makefile for all payloads

# Detect all immediate subdirectories (excluding . and ..) by matching directories ending with a slash and removing the trailing slash.
SUBDIRS := $(patsubst %/,%,$(wildcard */))

# Only keep subdirs that contain a Makefile
SUBDIRS := $(foreach dir,$(SUBDIRS),$(if $(wildcard $(dir)/Makefile),$(dir)))

.PHONY: all clean $(SUBDIRS)

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	@$(foreach dir,$(SUBDIRS),$(MAKE) -C $(dir) clean;)
