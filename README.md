
## Description
A basic, simple dynamic loader/linker implementation for Aarch64, to learn about dynamic linking and ELF file loading + execution (inspired by https://blog.cloudflare.com/fr-fr/how-to-execute-an-object-file-part-4/).
Due to libc-specific TLS (thread-local storage) implementation, only very basic programs (without threading) are supported.
### Build
Compile with `gcc loader.c asm.S -o <output-name>` (`-o` for debugging, `-mcpu=<target cpu>` to target a specific architecture (e.g. `cortex-a72` for RPi4))

### Usage
`<output-name> <ELF-file> <hex-main-address>`, where:
 - `<Elf-file>` is the dynamically-linked ELF file to be executed
 - `<hex-main-address>` is the address of the ELF's `main()` function in hexadecimal, can be displayed (from the static symbol table) by `readelf -s <executable> | grep ' main$'` (not the entry point `e_entry`)

Example of a supported simple program:
```
#include <stdio.h>
#include <unistd.h>

int main(int argc, char ** argv) {
        char * s = "hello, world!\n";
        if (write(1, s, 15) == -1) {
                return -1;
        }
        return 0;
}
```