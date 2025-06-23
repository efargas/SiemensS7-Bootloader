# Compilador y herramientas
CC       := clang                    # Compilador Clang para C
LD       := arm-none-eabi-ld         # Linker para sistemas embebidos ARM
STRIP    := arm-none-eabi-strip      # Elimina símbolos innecesarios del binario
OBJCOPY  := arm-none-eabi-objcopy    # Convierte entre formatos de archivos objeto

# Opciones de optimización
CFLAGS_OPT := \
    -Os                              # Optimiza para tamaño reducido

# Opciones del compilador
CFLAGS := \
    -std=c11                         # Usa estándar C11
    -ffreestanding                   # No se asume entorno estándar (sin librerías estándar ni main())
    -fno-builtin                     # Evita funciones internas del compilador (más control)
    -Wall                            # Muestra todas las advertencias
    -mcpu=cortex-r4                  # Target: ARM Cortex-R4
    -DGDBSTUB_PRINT                  # Define macro que probablemente habilita impresión para debugging
    -I../lib                         # Incluye headers desde ../lib
    -frwpi                           # RWPI (Read/Write Position Independent): memoria R/W independiente de posición
    -fropi                           # ROPI (Read-Only Position Independent): memoria R/O independiente de posición
    -mbig-endian                     # Endianness big-endian (MSB primero)
    -target arm-none-eabi            # Target sin sistema operativo: ARM Embedded ABI

# Script de enlace y opciones del linker
LDFLAGS := \
    -EB                              # Endianness big-endian
    -Tlink.ld                        # Usa script personalizado de enlace: link.ld
    -nostdlib                        # No enlaza librerías estándar automáticamente
    --gc-sections                    # Elimina secciones sin usar del binario

# Versión por defecto del firmware si no se define externamente
ifeq ($(FW_VER),)
FW_VER := 2
endif

# Define macro con la versión del firmware
CFLAGS += -DFW_VER=$(FW_VER)

