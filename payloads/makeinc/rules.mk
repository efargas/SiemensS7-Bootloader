MAKEFLAGS += -r
.SUFFIXES:
.SUFFIXES: .c .o .S

ifeq ($V, 1)
	VERBOSE =
else
	VERBOSE = @
endif

include ../makeinc/config.mk

# Allow linker script override
LINKER_SCRIPT ?= link.ld
LDFLAGS := -EB -T$(LINKER_SCRIPT) -nostdlib --gc-sections

# Place all object files in build/ with just the filename
OBJ := $(foreach f,$(SRC),build/$(notdir $(f:.c=.o)))
OBJ += $(foreach f,$(SRC_ASM),build/$(notdir $(f:.S=.o)))
DEP := $(OBJ:%.o=%.d)
INC := -I..

.PHONY: all clean build help

# Macro for creating directories
define make-dir
ifeq ($(OS),Windows_NT)
	@if not exist $(1) mkdir $(1)
else
	@mkdir -p $(1)
endif
endef

all: $(TARGET).ihex $(TARGET).bin | build

help:
	@echo "Available targets:"
	@echo "  all     - Build all outputs"
	@echo "  clean   - Remove build artifacts"
	@echo "  build   - Create build directory"
	@echo "  help    - Show this help message"

# Dependency tracking is disabled. If you want incremental rebuilds, uncomment the next line:
# -include $(DEP)

build:
	$(call make-dir,build)

# General pattern rule for compiling .c and .S files from any directory into build/
build/%.o: %.c | build
	@echo $(CC) $<
	$(call make-dir,$(dir $@))
	$(VERBOSE) $(ENV) $(CC) $(CFLAGS) $(CFLAGS_OPT) $(INC) $(DEF) -MMD -MT $@ -MF build/$*.d -o $@ -c $<

build/%.o: %.S | build
	@echo $(CC) $<
	$(call make-dir,$(dir $@))
	$(VERBOSE) $(ENV) $(CC) $(CFLAGS) $(CFLAGS_OPT) $(INC) $(DEF) -MMD -MT $@ -MF build/$*.d -o $@ -c $<

build/%.o: ../%/%.c | build
	@echo $(CC) $<
	$(call make-dir,$(dir $@))
	$(VERBOSE) $(ENV) $(CC) $(CFLAGS) $(CFLAGS_OPT) $(INC) $(DEF) -MMD -MT $@ -MF build/$*.d -o $@ -c $<

build/%.o: ../%/%.S | build
	@echo $(CC) $<
	$(call make-dir,$(dir $@))
	$(VERBOSE) $(ENV) $(CC) $(CFLAGS) $(CFLAGS_OPT) $(INC) $(DEF) -MMD -MT $@ -MF build/$*.d -o $@ -c $<

$(TARGET).sym: $(OBJ)
	@echo ld $(notdir $@)
	$(VERBOSE) $(ENV) $(LD) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

$(TARGET): $(TARGET).sym
	@echo strip $(notdir $@)
	$(VERBOSE) $(ENV) $(STRIP) $(TARGET).sym -o $@

$(TARGET).bin: $(TARGET)
	@echo objcopy $(notdir $@)
	$(VERBOSE) $(ENV) $(OBJCOPY) -O binary $(TARGET) $@

$(TARGET).ihex: $(TARGET)
	@echo objcopy $(notdir $@)
	$(VERBOSE) $(ENV) $(OBJCOPY) -O ihex $(TARGET) $@

clean:
ifeq ($(OS),Windows_NT)
	-@if exist build rmdir /S /Q build
	-@if exist lib rmdir /S /Q lib
	-@del /Q /F *.bin 2>nul
	-@del /Q /F *.ihex 2>nul
	-@del /Q /F *.sym 2>nul
	-@del /Q /F $(TARGET) 2>nul
	-@del /Q /F $(TARGET).sym 2>nul
	-@del /Q /F $(TARGET).bin 2>nul
	-@del /Q /F $(TARGET).ihex 2>nul
	-@del /Q /F *.d 2>nul
	-@del /Q /F *.o 2>nul
else
	$(VERBOSE) rm -rf build lib *.bin *.ihex *.sym $(TARGET) $(TARGET).sym $(TARGET).bin $(TARGET).ihex *.d *.o
endif
