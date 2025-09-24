#include <stdint.h>
#include <elf.h>
#include <sys/ifunc.h>

#ifndef LOADER_H
#define LOADER_H

int mmap_segments(Elf64_Phdr **, int, int fd, uint64_t *);
Elf64_Sym * lookup_symbol_module(const char *, uint32_t *, char *, Elf64_Sym *);


typedef struct{
  int num_headers;
  Elf64_Phdr * headers;
  uint64_t entry_point;  // entry point, if ELF is executable, the only info later needed from the ELF header
} ProgramHeaders;

typedef struct ElfModule ElfModule;

// mimic the TLS data structure used in AArch64,
// which follows Drepper's (https://uclibc.org/docs/tls.pdf) variant I
// see also glibc-Aarch64: https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/aarch64/nptl/tls.h;h=200334f84a2ba0564a84c1243c9b6b261bba0f5d;hb=437faa9675dd916ac7b239d4584b932a11fbb984#l46
typedef struct {
  // dynamic thread vector, contains pointers for each module (indexed by the module id,
  // starting at 0 instead of 1, omitting the 'gen' field) to their TLS block in the TLS image for a thread
  uint8_t ** dtv;
  void * private;  // not used

  // flexible array member containing the (dynamically allocated) TLS image (concatenation of all loaded modules' TLS segments) as contiguous block
  // needs to be (at least for the executable module itself) directly located (16 bytes) after the pointer to the dtv and TCB/private data,
  // to support the local-exec access model, where the executable module accesses thread-local variables via a fixed offset from the thread pointer,
  // assuming its TLS block being located directly after aforementioned header
  uint8_t data[];
} TLS_t;


typedef struct {
  ElfModule * root;  // the root module of the loaded depdendency graph; the main executable module
  int num_modules;  // current number of loaded modules, will be assigned as module id for the next loaded module
  
  // needed for IFUNC resolvers (R_AARCH64_IRELATIVE relocations)
  uint64_t at_hwcap;
  __ifunc_arg_t hwcap_struct;
  // initial (static) TLS image, is also used for main thread, as threading not supported (would need to adhere to glibc...)
  TLS_t * tls;
  void * stack;  // stack for executing functions (initialization, main entry point) on
} ElfLoaderCtx;

// info about a TLS segment
typedef struct {
  uint64_t start;
  uint64_t filesz;
  uint64_t memsz;
  int align;
  ElfModule * m;
} TLS_Block_t;


struct ElfModule {
  ElfLoaderCtx * ctx;  // back reference to associated context
  int module_id;  // a unique id, strictly increasing from 0
  void * entry_point;
  uint64_t map_offset;
  Elf64_Dyn * dynamic;  // pointer to first element of DT_DYN
  char * soname;
  char * path;
  char * interp;
  char * strtab;
  uint64_t flags;
  uint64_t flags1;
  uint32_t * gnu_hash;
  Elf64_Sym * symtab;
  int num_dependencies;
  ElfModule** dependencies;  // pointers to all loaded dependencies
  uint64_t * plt_got;
  uint64_t plt_rel_sz;
  uint64_t plt_rel;
  union {
    Elf64_Rel * rel;
    Elf64_Rela * rela;
  } jmprel;
  Elf64_Rel * rel;
  uint64_t num_rel;
  Elf64_Rela * rela;
  uint64_t num_rela;
  TLS_Block_t * tls_info;

  uint64_t preinit_arr_sz;
  uint64_t init_arr_sz;
  uint64_t fini_arr_sz;
  void * preinit_arr;
  void * init_arr;
  void * fini_arr;
  void * init;
  void * fini;
};

typedef struct {
  char * strtab;
  Elf64_Sym * symtab;
  int num_dependencies;
  char ** dependencies;
  char * soname;
  uint32_t * gnu_hash;
  uint64_t flags;
  uint64_t flags1;
  uint64_t * plt_got;
  uint64_t plt_rel_sz;
  uint64_t plt_rel;
  uint64_t * jmprel;
  Elf64_Rel * rel;
  uint64_t num_rel;
  Elf64_Rela * rela;
  uint64_t num_rela;

  uint64_t preinit_arr_sz;
  uint64_t init_arr_sz;
  uint64_t fini_arr_sz;
  void * preinit_arr;
  void * init_arr;
  void * fini_arr;
  void * init;
  void * fini;
} DynInfo;

#endif /* LOADER_H */