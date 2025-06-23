# Makefile for hello_world
BIN=hello_world.bin
SRC=hello_world.s
TMP=tmp.elf

all: $(BIN)

$(BIN): $(SRC)
	arm-none-eabi-as -EB -o $(TMP) $(SRC)
	arm-none-eabi-objcopy -j .text -Obinary $(TMP) $(BIN)
ifeq ($(OS),Windows_NT)
	del /Q $(TMP)
else
	rm -f $(TMP)
endif

clean:
ifeq ($(OS),Windows_NT)
	@if exist $(BIN) del /Q $(BIN)
	@if exist $(TMP) del /Q $(TMP)
else
	@if [ -f $(BIN) ]; then rm -f $(BIN); fi
	@if [ -f $(TMP) ]; then rm -f $(TMP); fi
endif
