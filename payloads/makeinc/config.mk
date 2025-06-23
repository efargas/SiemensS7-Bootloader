# Compilador y herramientas
CC       := arm-none-eabi-gcc         # Compilador GCC para ARM
LD       := arm-none-eabi-ld         # Linker para sistemas embebidos ARM
STRIP    := arm-none-eabi-strip      # Elimina símbolos innecesarios del binario
OBJCOPY  := arm-none-eabi-objcopy    # Convierte entre formatos de archivos objeto

# Opciones de optimización
CFLAGS_OPT := \
    -Os                              # Optimiza para tamaño reducido

# Opciones del compilador
CFLAGS := \
    -std=c11 \
    -ffreestanding \
    -fno-builtin \
    -Wall \
    -mcpu=cortex-r4 \
    -DGDBSTUB_PRINT \
    -I../lib \
    -mbig-endian

# Script de enlace y opciones del linker
LDFLAGS := \
    -EB \
    -Tlink.ld \
    -nostdlib \
    --gc-sections

# Versión por defecto del firmware si no se define externamente
ifeq ($(FW_VER),)
FW_VER := 2
endif

# Define macro con la versión del firmware
CFLAGS += -DFW_VER=$(FW_VER)

