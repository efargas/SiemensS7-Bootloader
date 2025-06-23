# Makefile for stager
BIN=stager.bin
SRC=stager.s
TMP=tmp.elf

all: $(BIN)

$(BIN): $(SRC)
	arm-none-eabi-as -EB -o $(TMP) $(SRC)
	arm-none-eabi-objcopy -j .text -Obinary $(TMP) $(BIN)
	@if [ "$(OS)" = "Windows_NT" ]; then del /Q $(TMP); else rm -f $(TMP); fi

clean:
	@if [ "$(OS)" = "Windows_NT" ]; then del /Q $(BIN) $(TMP); else rm -f $(BIN) $(TMP); fi
