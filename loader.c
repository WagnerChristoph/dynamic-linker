#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <elf.h>  // needs to be from the Aarch64 toolchain
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/auxv.h>
#include <sys/ifunc.h>
#include <linux/limits.h>
#include <fcntl.h>
#include "loader.h"


/* 
A (simplified) Implementation of an dynamic linker/loader for Aarch64, imitating the functionality of (glibc) 'ld-linux.so'.
Loads a dynamcially-linked ELF file into mememory, parses and recursively resolves its dependencies in a depth-first fashion and in turn loads
all those necessary dependencies into memory, constructing a dependency graph of loaded modules.
Then for all modules:
 - gathers their TLS segments to create a single TLS image (for the main thread)
 - process and resolve their relocations
 - call initialization routines
After initialization, a stack is allocated and control is tranferred to the main executable to run the module's entry point, and upon returning,
finalization routines are executed and the program's returned value is return.

- Features:
 - automatic recursive dependency resolution (supports the environment variable 'LD_LIBRARY_PATH' and 'DT_RUNPATH' dynamic tags)
 - PLT relocations: either resolved eagerly upfront (flag 'DF_BIND_NOW') or on-demand lazily through callback inserted into .got.plt (as per the ABI)
 - symbol lookup (in a module and its dependencies) through GNU_HASH table (fast due to the use of bloomfilters), legacy hash table not supported
 - basic TLS implementation
 - implementation of most (common) dynamic relocation types (except 'R_AARCH64_TLSDESC' 'R_AARCH64_COPY' and PAuth ABI Extension's)
 - IFUNC (relocation type 'R_AARCH64_IRELATIVE') support
 - RELR relocation (compressed relative relocations) support
 - program execution on separate stack

Because the (glibc) libc, threads and dynamic linker implementation are tightly coupled and used common internal data structures (and are not independent 
from one another and do not rely on common standards/conventions alone), this is only a simplified implementation of the core functionality.
Especially the TLS implementation/data structures and the interaction with threading libraries are difficult to recreate, so that only simple programs (without threading)
and minimal threadlocal accesses are reliably supported. (see also https://wiki.musl-libc.org/design-concepts)

Notes:
 - main executable module (ELF) is expected to be a dynamically-linked PIE
 - Thread Local Storage:
  - only a very basic support of (static) TLS is implemented, i.e. TLS of the main executable and its dependencies, not of
    modules loaded via dlopen (dynamic TLS)
  - basic support is required due to glibc (libc.so.6) having a TLS segment (and tls-related relocations)
  - only the TLS image of the main thread is supported, no copying/creating of another thread (via pthread/threads.h)
  - is implemented similar to Drepper's data structures (https://uclibc.org/docs/tls.pdf), variant I, but module IDs start
  (with the main executable) at 0, not 1
  - support for the local-exec (fixed offset), initial-exec (variable lookup via GOT) models, the general/global-dynamic would require
  knowledge/implementation (with on-demand loading?) of the '__tls_get_addr' function; TLS descriptors are also not implemented (due to complexity)

 - 'LD_BIND_NOW' not supported
 - dynamic loading of additional modules (akin to 'dlopen') currently not supported
 - flags: only 'DF_BIND_NOW' and 'DF_1_NOW' are supported
 - 'GNU_STACK'/'GNU_RELRO' not supported
 - versioned symbol names not supported
*/

extern int dl_asm_resolve();

uint32_t gnu_hash(const char * name) {
    uint32_t h = 5381;
    unsigned char c;
    while ((c = *name++) != '\0') {
        h = (h << 5) + h + c;
    }
    return h;
}

int read_initial_section(int fd, uint64_t e_shoff, Elf64_Shdr * p) {
    if (lseek(fd, e_shoff, SEEK_SET) == -1) {
        perror("lseek");
        return -1;
    }
    if (read(fd, p, sizeof(Elf64_Shdr)) != sizeof(Elf64_Shdr)) {
        perror("read");
        return -1;
    }
    return 0;
}


void deduplicate_deps(DynInfo * dyn_info) {
    char **unique_deps = calloc(dyn_info->num_dependencies, sizeof(char *));
    int unique_count = 0;
    for (size_t i = 0; i < dyn_info->num_dependencies; i++) {
        bool is_dup = 0;
        for (int j = 0; j < unique_count; j++) {
            if (strcmp(dyn_info->dependencies[i], unique_deps[j]) == 0) {
                is_dup = 1;
                break;
            }
        }
        if (!is_dup) {
            unique_deps[unique_count++] = dyn_info->dependencies[i];
        } else {
            // free unused string
            free(dyn_info->dependencies[i]);
        }
    }
    free(dyn_info->dependencies);  // free old list
    dyn_info->dependencies = unique_deps;
    dyn_info->num_dependencies = unique_count;
}

void free_dyn_info(DynInfo * dyn_info) {
    // check if dependencies is a valid dynamically-allocated array
    if (dyn_info->dependencies) {
        // free all valid contained dependencies
        for (size_t i = 0; i < dyn_info->num_dependencies; i++) {
            if (dyn_info->dependencies[i]) {
                free(dyn_info->dependencies[i]);
            }
        }
        // free dependencies array itself
        free(dyn_info->dependencies);
    }
}

/**
 * @brief Checks whether the specified file exists and is a regular file (following symlinks)
 */
bool file_exists(const char * path) {
    struct stat st;
    // does follow symlinks, as opposed to 'lstat'
    if (stat(path, &st) == 0) {
        // check if regular file (https://man7.org/linux/man-pages/man7/inode.7.html)
        if (S_ISREG(st.st_mode)) {
            return 1;
        }
    }
    return 0;
}

void join_path(char *buffer, size_t bufsize, const char *dir, const char *file) {
    size_t dir_len = strlen(dir);
    bool need_slash = 0;
    if (dir_len > 0 && dir[dir_len - 1] != '/') {
        need_slash = 1;
    }
    if (need_slash) {
        snprintf(buffer, bufsize, "%s/%s", dir, file);
    } else {
        snprintf(buffer, bufsize, "%s%s", dir, file);
    }
}


/**
 * @brief Resolve a symbol name in the given module or its direct dependencies. Versioned symbol names are not supported,
 * version suffix is ignored (anything after '@'). At first, the symbol is attempted to be resolved in the module itself,
 * if unsuccessful, the module's direct dependency modules are tried.
 * 
 * @param symbol_name The name of the symbol to resolve.
 * @param m The module in which (and its direct dependencies) to resolve the symbol
 * @param sym_module If symbol is found, set to the module containing the symbol.
 * @return Elf64_Sym* Pointer to the resolved symbol if resolution was successful or NULL is symbol could not be found.
 */
Elf64_Sym * resolve_symbol_addr(const char *symbol_name, ElfModule *m, ElfModule ** sym_module) {
    // note:
    // for simplification, search symbol only in direct dependencies, not in a breadth-first manner
    // traversing the entire dependency graph

    // ignore symbol versioning, i.e. the versioned symbol name,
    // where the version string is appended after the symbol name with a prefixed '@'
    // ('@@' denoting the default version
    char * s = strdup(symbol_name);
    char * tok = strtok(s, "@");  // cut off anything after first '@'

    if (!tok) {
        free(s);
        return NULL;
    }

    ElfModule *fm = NULL;
    // try to find the symbol in the module itself
    Elf64_Sym *sym = lookup_symbol_module(tok, m->gnu_hash, m->strtab, m->symtab);
    if (sym && sym->st_shndx != SHN_UNDEF) {
        // symbol has been found and is defined
        fm = m;
    } else {
        // search in direct dependencies
        for (size_t i = 0; i < m->num_dependencies; i++) {
            ElfModule *d = m->dependencies[i];
            if (!d) {
                continue;
            }
            sym = lookup_symbol_module(tok, d->gnu_hash, d->strtab, d->symtab);
            if (sym && sym->st_shndx != SHN_UNDEF) {
                fm = d;
                break;
            }
        }
    }

    if (fm && sym_module) {
        *sym_module = fm;
    }
    free(s);
    return sym;
}

/**
 * @brief BFS traversal
 * 
 * @param m The current module (start with ctx->root)
 * @param visited Array of bools to mark visited modules (size: ctx->num_modules)
 * @param callback Function pointer to call for each module (void (*callback)(ElfModule *, void *))
 * @param user_data Opaque pointer passed to callback
 * @param self_first Whether the callback should be invoked on the module itself first before invoking on the module's dependencies
 * @return int 0 if all callback invocation returnd 0, or the first non-zero value any callback returned
 */
int _visit_dfs(ElfModule *m, bool *visited, int (*callback)(ElfModule *, void *), void *user_data, bool self_first) {
    int res = 0;
    if (!m || visited[m->module_id]) {
        return res;
    }
    visited[m->module_id] = 1;
    if (self_first) {
        res = callback(m, user_data);
        for (size_t i = 0; i < m->num_dependencies; i++) {
            res = _visit_dfs(m->dependencies[i], visited, callback, user_data, self_first);
            if (res) {
                break;
            }
        }
    } else {
        for (size_t i = 0; i < m->num_dependencies; i++) {
            res = _visit_dfs(m->dependencies[i], visited, callback, user_data, self_first);
            if (res) {
                break;
            }
        }
        res = callback(m, user_data);
    }
    if (res) {
        return res;
    }
    return res;
}

/**
 * @brief Helper to start BFS traversal from the context root.
 * 
 * @param ctx Pointer to ElfLoaderCtx
 * @param callback Function pointer to call for each module, signals with return value whether to continue; any return value other than 0 aborts the traversal
 * @param user_data Opaque pointer passed to callback
 * @return int 0 if successfully traversed all nodes, or the first non-zero return value of any invoked callback.
 */
int visit_dfs(ElfLoaderCtx *ctx, int (*callback)(ElfModule *, void *), void *user_data) {
    if (!ctx || !ctx->root) {
        return 0;
    }
    bool *visited = calloc(ctx->num_modules, sizeof(bool));
    int res = _visit_dfs(ctx->root, visited, callback, user_data, 0);
    free(visited);
    return res;
}

// Same as above, but each node itself is processed before its neighbors/dependencies
int visit_dfs_reverse(ElfLoaderCtx *ctx, int (*callback)(ElfModule *, void *), void *user_data) {
    if (!ctx || !ctx->root) {
        return 0;
    }
    bool *visited = calloc(ctx->num_modules, sizeof(bool));
    int res = _visit_dfs(ctx->root, visited, callback, user_data, 1);
    free(visited);
    return res;
}

/**
 * @brief Process a single parsed (dynamic) relocation.
 * 
 * @param m The module the relocation is associated to
 * @param sym_idx The symbol index of the relocation (references a symbol in the module's symbol table)
 * @param rel_type The relocation's type
 * @param addend The relocation's addend
 * @param reloc_addr If successful, will contain the relocations result.
 * @return int 0 if successful, -1 else.
 */
int resolve_reloc(ElfModule *m, uint64_t sym_idx, uint64_t rel_type, uint64_t addend, uint64_t * reloc_addr) {
    // see: https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/aarch64/dl-machine.h;h=022642ae83e85e83c8ea6706a53842bea32d3724;hb=HEAD#l169

    Elf64_Sym * sym;
    ElfModule * fm;
    Elf64_Sym * lsym;

    switch (rel_type) {
        case R_AARCH64_RELATIVE:
            // if the referenced symbol is the reserved symbol (symbol index 0), take the offset (difference
            // between link and load address) of the relocated place (r_offset) instead of the referenced symbol;
            // but, as the mapping offset is identical for all loaded segments, the offset is identical in all cases,
            // and the symbol can be ignored
            *reloc_addr = m->map_offset + addend;
            break;
        case R_AARCH64_IRELATIVE:
            // build address of ifunc resolver function (see sys/ifunc.h), the addend effectively is the address of the resolver function
            // see: https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/aarch64/dl-irel.h;h=7bae3c3c4908e87025c891f87552f72a0bbd750b;hb=HEAD
            // symbol is ignored as above
            uint64_t (*resolver)(uint64_t, const __ifunc_arg_t *) = (void*) m->map_offset + addend;
            // call resolver function (arguments defined by SysV ABI)
            // returns chosen function address
            *reloc_addr = resolver(m->ctx->at_hwcap, &m->ctx->hwcap_struct);
            break;
        case R_AARCH64_ABS64:
        case R_AARCH64_GLOB_DAT:
        case R_AARCH64_JUMP_SLOT:
            // the absolute value of the referenced (data, in case of R_AARCH64_GLOB_DATE (for the GOT)) symbol
            // or function (R_AARCH64_JUMP_SLOT)
            sym = &m->symtab[sym_idx];

            lsym = resolve_symbol_addr(&m->strtab[sym->st_name], m, &fm);
            if (!lsym) {
                // could not be resolved
                if (ELF64_ST_BIND(sym->st_info) == STB_WEAK) {
                    // unresolved weak symbols are defined to have value 0 (instead of an error)
                    *reloc_addr = 0;
                    return 0;
                }
                fprintf(stderr, "could not resolve symbol '%s'\n", m->strtab + m->symtab[sym_idx].st_name);
                return -1;
            }
            *reloc_addr = (uint64_t) lsym->st_value + fm->map_offset + addend;
            break;
        case R_AARCH64_TLS_TPREL:
        case R_AARCH64_TLS_DTPREL:
        case R_AARCH64_TLS_DTPMOD:

            // thread pointer points to start of tls structure
            TLS_t * t = m->ctx->tls;
            if (!t){
                fprintf(stderr, "missing TLS image\n");
                return -1;
            }
            sym = &m->symtab[sym_idx];
            if (sym_idx) {
                lsym = resolve_symbol_addr(&m->strtab[sym->st_name], m, &fm);
                if (!lsym) {
                    fprintf(stderr, "could not resolve symbol '%s'\n", m->strtab + m->symtab[sym_idx].st_name);
                    return -1;
                }
                switch (rel_type) {
                    case R_AARCH64_TLS_TPREL:
                        // used in the initial-exec model, resolves to the thread-pointer relative offset of the symbol,
                        // suitable only for static TLS (uses a GOT slot)
                        *reloc_addr = ((uint64_t) t->dtv[fm->module_id]) + lsym->st_value + addend;
                        break;
                    // the following two relocations are used in pairs in the global-dynamic access model for the (c-stdlib defined?) '__tls_get_addr' function,
                    // suitable especially for dynamic TLS (modules loaded via dlopen)
                    // Aarch64 uses TLS descriptors for global-dynamic as default instead
                    case R_AARCH64_TLS_DTPREL:
                        // intra-TLS-block offset of symbol
                        *reloc_addr = lsym->st_value + addend;
                        break;
                    case R_AARCH64_TLS_DTPMOD:
                        // module id
                        *reloc_addr = fm->module_id;
                        break;

                    // note: TLS descriptors not implemented (R_AARCH64_TLSDESC)
                    default:
                        fprintf(stderr, "invalid relocation type '%#lx'\n", rel_type);
                        return -1;
                }
            }  // TLS relocations referencing the '0' symbol (found e.g. in libc) are ignored (as does glibc)
            break;
        default: 
            fprintf(stderr, "unsupported relocation type '%#lx'\n", rel_type);
            return -1;
        }
    return 0;
}

// process a single RELA-type relocation
int reloc_rela(ElfModule *m, Elf64_Rela * rela, uint64_t * result) {
    uint64_t rel_type = ELF64_R_TYPE(rela->r_info);
    uint64_t rel_sidx = ELF64_R_SYM(rela->r_info);
    uint64_t reloc;
    if (resolve_reloc(m, rel_sidx, rel_type, rela->r_addend, &reloc) == -1) {
        return -1;
    }
    // apply relocation
    *(uint64_t *) (rela->r_offset + m->map_offset) = reloc;
    *result = reloc;

    return 0;
}

// process a single REL-type relocation
int reloc_rel(ElfModule *m, Elf64_Rel * rel, uint64_t * result) {
    int64_t addend = 0;
    uint64_t rel_type = ELF64_R_TYPE(rel->r_info);
    uint64_t rel_sidx = ELF64_R_SYM(rel->r_info);

    // for REL type relocations, the implicit addend is the value initially stored at the relocated place,
    // except for 'R_AARCH64_JUMP_SLOT', where the addend is defined to be 0 (therefore ignored)
    // (as the value initially stored at the relocated place (at the .got.plt entry (the PLT base address))
    // is not related to the relocation target) 
    if (rel_type != R_AARCH64_JUMP_SLOT) {
        addend = * (uint64_t *)rel->r_offset;
    }
    uint64_t reloc;
    if (resolve_reloc(m, rel_sidx, rel_type, addend, &reloc) == -1) {
        return -1;
    }
    // apply relocation
    *(uint64_t *) (rel->r_offset + m->map_offset) = (uint64_t) reloc;
    *result = reloc;

    return 0;
}

int reloc_relr(ElfModule *m, Elf64_Relr * relr, int size) {
    // handle new RELR-relocation, which are compressed REL (implicit addend stored at relocated place) relative relocations
    // https://gabi.xinuos.com/elf/06-reloc.html#relative-relocation-table
    // https://dram.page/p/relative-relocs-explained/

    // the distance between the previous address entry and the word which the LSB of the current bitmap entry refers to
    int dist = 1;  
    uint64_t p = 0;  // the previously seen address entry, to which the possible following bitmap entry words refer to
    for (size_t i = 0; i < size; i++) {
        uint64_t e = (uint64_t) relr[i];  // current entry
        if (!(e & 1ull)) {  // if LSB is cleared, entry is an address entry
            dist = 1;  // reset distance for possible next bitmap entry word
            p = e;  // set current address entry
            *(uint64_t *)(e + m->map_offset) += m->map_offset;  // apply relative relocation
        } else {
            for (size_t i = 0; i < 63; i++) {  // iterate over all (except LSB) bits
                if ((e >> (i+1)) & 1ull) {  // if bit is set
                    *((uint64_t *)(p + m->map_offset) + dist + i) += m->map_offset;  // apply relative relocation
                }
            }
            dist += 63;  // distance for next bitmap word is increased by 63
        }
    }
    return 0;


    // uint64_t * p = NULL;  // the relocated place
    // int pos = 0;
    // Elf64_Relr a = relr[pos];
    // int dist = 1;
    // if (!(a & 1ull)) {
    //     p = (uint64_t*)(a + m->map_offset);
    //     *p += m->map_offset;
    // } else {
    //     uint64_t e = a;
    //     for (size_t i = 0; i < 63; i++){
    //         if ((e >> (i+1)) & 1ull) {
    //             // relocate
    //             p = (uint64_t*) (a + dist + m + m->map_offset);
    //             *p += m->map_offset;
    //         }
    //     }
    //     dist += 63;
        
    // }
}


/**
 * @brief Intended to be called as (on-demand/lazy) resolution function for PLT entries, from a asm veneer/shim, that arranges the arguments in a practical way.
 * As there is no way to communicate resolution failure, this function aborts the whole process if the requested function name cannot be resolved.
 * 
 * @param entry_point_addr Pointer to /address of .got.plt[2] (which by convention contains the address of the resolver routine),
 * which is needed to identify the calling module (and is provided in the convential/ABI PLT resolution mechanism) 
 * @param resolve_entry Pointer to the entry in the got.plt to be resolved
 * @return uint64_t The resolved address of the requested .got.plt entry
 */
uint64_t plt_resolve(uint64_t * entry_point_addr, uint64_t * resolve_entry){
    // identify the requesting module/ the module the requested .got.plt entry belongs to, by accessing the private information (word-size), stored upon loading 
    // at .got.plt[1]
    ElfModule *m = *(ElfModule**) (entry_point_addr -1);
    // determine the requested .got.plt entry index (by subtracting the base address of .got.plt (which in turn is accessed from the module)),
    // which is identical to the related relocations (.rel[a].plt) table index
    uint64_t reloc_idx = (((uint64_t)resolve_entry) - ((uint64_t)m->plt_got))/8;
    uint64_t result;
    int success;
    if (m->plt_rel == DT_REL){
        // adjust for first 3 reserved entries
        success = reloc_rel(m, &m->jmprel.rel[reloc_idx -3], &result);
    } else {
        success = reloc_rela(m, &m->jmprel.rela[reloc_idx] -3, &result);
    }

    if (success == -1){
        abort();
    }
    return result;
}


void prepare_got_plt(uint64_t * got_plt, uint64_t map_offset, ElfModule * module, uint64_t num_slots) {
    // all .got.plt entries need to be prepared upon loading:
    // first 3 entries are reserved
    got_plt[1] = (uint64_t) module;  // second entry can contain private information and is used to identify the calling module, here a pointer to the module
    got_plt[2] = (uint64_t) &dl_asm_resolve;  // third entry contains resolver function address (entry point)
    // all other entries contain the link address of PLT[0], which needs to be adjusted by the mapping offset (load addresses)
    for (size_t i = 3; i < num_slots; i++) {
        got_plt[i] += map_offset;
    }
}

/**
 * @brief Process (resolve) all of a module's relocations (DT_REL and DT_RELA).
 * 
 * @param m The module of which to process the relocations of
 * @param n unused 
 * @return int 0 if successful, -1 else.
 */
int process_relocs(ElfModule * m, void * n) {
    uint64_t reloc;  // relocation result, ignored
    if (m->rel) {
        for (size_t i = 0; i < m->num_rel; i++) {
            if (reloc_rel(m, &m->rel[i], &reloc) == -1) {
                fprintf(stderr, "error processing REL relocation at index %ld in module %s (id %d)\n", i, m->soname, m->module_id);
                return -1;
            }
        }
        printf("processed %ld REL relocations for module %d\n", m->num_rel, m->module_id);
    }
    if (m->rela) {
        for (size_t i = 0; i < m->num_rela; i++) {
            if (reloc_rela(m, &m->rela[i], &reloc) == -1) {
                fprintf(stderr, "error processing RELA relocation at index %ld in module %s (id %d)\n", i, m->soname, m->module_id);
                return -1;
            }
        }
        printf("processed %ld RELA relocations for module %d\n", m->num_rela, m->module_id);
    }
    if (m->relr) {
        if (reloc_relr(m, m->relr, m->num_relr)) {
            fprintf(stderr, "error processing RELR relocations in module %s (id %d)\n", m->soname, m->module_id);
            return -1;
        }
        printf("processed RELR relocations in module %s (id %d\n", m->soname, m->module_id);
    }
    
    return 0;
}

/**
 * @brief Process all the modules PLT-related relocations. Intended for if all PLT relocations should be resolved eagerly.
 * 
 * @param m The module of which to resolve the PLT relocations of
 * @param n unused
 * @return int 0 if successful, -1 else.
 */
int process_plt_relocs(ElfModule * m, void * n) {
    uint64_t reloc;  // relocation result, ignored 
    uint64_t num_relocs;
    if (m->plt_rel == DT_RELA) {
        num_relocs = m->plt_rel_sz / sizeof(Elf64_Rela);
        for (size_t i = 0; i < num_relocs; i++) {
            if (reloc_rela(m, &m->jmprel.rela[i], &reloc) == -1) {
                fprintf(stderr, "error processing plt RELA relocation at index %ld in module %s (id %d)\n", i, m->soname, m->module_id);
                return -1;
            }
        }
        printf("processed %ld plt RELA relocations for module %d\n", num_relocs, m->module_id);
    } else if (m->plt_rel == DT_REL) {
        num_relocs = m->plt_rel_sz / sizeof(Elf64_Rel);
        for (size_t i = 0; i < num_relocs; i++) {
            if (reloc_rel(m, &m->jmprel.rel[i], &reloc) == -1) {
                fprintf(stderr, "error processing plt REL relocation at index %ld in module %s (id %d)\n", i, m->soname, m->module_id);
                return -1;
            }
        }
        printf("processed %ld plt REL relocations for module %d\n", num_relocs, m->module_id);
    } else {
        fprintf(stderr, "invalid relocation type %ld\n", m->plt_rel);
        return -1;
    }
    return 0;
}

int module_handle_plt(ElfModule * m, void * n) {
    if (m->flags & DF_BIND_NOW || m->flags1 & DF_1_NOW) {  // treat both flags equivalently
        return process_plt_relocs(m, n);
    }
    return 0;
}

/**
 * @brief Tries to resolve a library name (return a path to a file with identical name) in the following way:
 *  - If the name contains a slash, it is interpreted as an abnsolute/relative path
 *  - If the name does not contain a slash, search for the name in the following order:
 *   - try to resolve against the list of directories contained in the environment variable
 *      'LD_LIBRARY_PATH' (list of directory names separated by ':' or ';'); unlike 'ld.so', does 
 *      not support dynamic string tokens (e.g. '$ORIGIN')
 *   - use the provided list of strings (intended to be used as the .dynamic DT_RUNPATH paths), where each
 *      string may contain multiple, ':'-separated directory paths (as above)
 *   - use the system default library paths like (on Aarch64): '/lib', '/lib/aarch64-linux-gnu'
 *  Returns the resolved path as string, that needs to be free'd, or NULL if not found
 * 
 *  Resolution rules akin to 'ld.so' (https://man7.org/linux/man-pages/man8/ld.so.8.html)
 * 
 * @param name The library name to resove
 * @param runpaths An array of strings contributing additional search paths
 * @param num_runpaths The size of above string array
 * @return char* Dynamically allocated string (needs to be free'd) if name was resolved, NULL else
 */
char * resolve_name(char * name, char ** runpaths, int num_runpaths) {
    // default library search paths
    char * lib_paths[] = {"/lib", "/lib/aarch64-linux-gnu"};

    char full_path[PATH_MAX];
    char * delim = ":;";

    // whether name contains a slash
    if (strchr(name, '/')) {
        // name is relative/absolute pathname
        if (file_exists(name)) {
            return strdup(name);
        }
        return NULL;
    }

    // use 'LD_LIBRARY_PATH'
    char * ld_library_path = getenv("LD_LIBRARY_PATH");
    if (ld_library_path) {
        char * lp = strdup(ld_library_path);
        // split string
        for (char * tok = strtok(lp, delim); tok; tok = strtok(NULL, delim)) {
            join_path(full_path, PATH_MAX, tok, name);
            if (file_exists(full_path)) {
                free(lp);
                return strdup(full_path);
            }
        }
        free(lp);
    }

    // use runpaths
    for (size_t i = 0; i < num_runpaths; i++) {
        char * rp = strdup(runpaths[i]);
        for (char * tok = strtok(rp, delim); tok; tok = strtok(NULL, delim)) {
            join_path(full_path, PATH_MAX, tok, name);
            if (file_exists(full_path)) {
                free(rp);
                return strdup(full_path);
            }
        }
        free(rp);
    }

    // use system default library paths
    for (size_t i = 0; i < sizeof(lib_paths)/sizeof(lib_paths[0]); i++) {
        join_path(full_path, PATH_MAX, lib_paths[i], name);
        if (file_exists(full_path)) {
            return strdup(full_path);
        }
    }
    return NULL;
}


/**
 * @brief Read and parse the specified ELF file and return its program header table's entries.
 * 
 * @param fd A opened file descriptor of an executable/shared ELF file.
 * @return ProgramHeaders* An Object containing the ELF file's program header with associated metadata. Is dynamically allocated, so must be freed on exit.
 * On any error or on an incompatible ELF file, NULL is returned.
 */
ProgramHeaders * read_program_headers(int fd) {
    // see: https://github.com/torvalds/linux/blob/cec1e6e5d1ab33403b809f79cd20d6aff124ccfe/fs/binfmt_elf.c#L505
    Elf64_Ehdr elf_hdr;
    if (lseek(fd, 0, SEEK_SET) == -1) {
        perror("lseek");
        return NULL;
    }
    // read ELF header first (fixed size)
    if (read(fd, &elf_hdr, sizeof(elf_hdr)) != sizeof(elf_hdr)) {
        fprintf(stderr, "Failed to read ELF header\n");
        return NULL;
    }
    // basic ELF header checks
    if (memcmp(elf_hdr.e_ident, "\x7f""ELF", 4) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        return NULL;
    }
    if (elf_hdr.e_ident[4] != ELFCLASS64) {
        fprintf(stderr, "Not a 64-bit ELF file\n");
        return NULL;
    }
    if (elf_hdr.e_ident[5] != ELFDATA2LSB) {
        fprintf(stderr, "Not a little-endian ELF file\n");
        return NULL;
    }
    if (elf_hdr.e_machine != EM_AARCH64) {
        fprintf(stderr, "Not an Aarch64 ELF file\n");
        return NULL;
    }
    // ELF must be either PIE or shared library (both use ET_DYN)
    if (elf_hdr.e_type != ET_DYN) {
        fprintf(stderr, "Not a PIE or shared library file\n");
        return NULL;
    }

    // program header table is mandatory for executable files
    if (elf_hdr.e_phoff == 0) {
        fprintf(stderr, "missing program header table\n");
        return NULL;
    }
    // ignore e_phentsize and e_shentsize

    uint64_t ph_num = elf_hdr.e_phnum;  // number of program header table entries
    if (ph_num == PN_XNUM) {
        // true count is in first section (reserved) header's sh_info field
        Elf64_Shdr res_section;
        if (elf_hdr.e_shoff == 0) {
            fprintf(stderr, "missing section header table\n");
            return NULL;
        }
        if (read_initial_section(fd, elf_hdr.e_shoff, &res_section)) {
            fprintf(stderr, "could not read initial section table entry\n");
            return NULL;
        }
        ph_num = res_section.sh_info;
    }

    // read program headers from file
    Elf64_Phdr * program_headers = malloc(sizeof(Elf64_Phdr) * ph_num);
    if (!program_headers) {
        perror("malloc");
        return NULL;
    }
    if (lseek(fd, elf_hdr.e_phoff, SEEK_SET) == -1) {
        perror("lseek");
        free(program_headers);
        return NULL;
    }
    if (read(fd, program_headers, sizeof(Elf64_Phdr) * ph_num) != sizeof(Elf64_Phdr) * ph_num) {
        fprintf(stderr, "error reading program header table\n");
        free(program_headers);
        return NULL;
    }
    ProgramHeaders * ph = malloc(sizeof(ProgramHeaders));
    if (!ph) {
        perror("malloc");
        free(program_headers);
        return NULL;
    }
    // set fields
    ph->num_headers = ph_num;
    ph->headers = program_headers;
    ph->entry_point = elf_hdr.e_entry;
    return ph;
}

/**
 * @brief Read and parse the specified ELF file and map its loadable segments into memory, returning its program header table's entries,
 * with associated metadata (number of entries and entry point address).
 * 
 * @param fd The opened file descriptor of the executable/shared ELF file to load.
 * @param map_offset If successful (return value not NULL) the mapping offset of the mapped segments (difference between link/load addresses).
 * @return ProgramHeaders* An Object containing all the ELF file's program headers, along associated metadata or NULL in case of an error. The returned 
 * program headers are separately dynamically allocated and do not point to the mapped file in memory (as not all entries are mapped in memory).
 */
ProgramHeaders * load_elf(int fd, uint64_t * map_offset) {
    // to be able to map the program into memory, read the ELF header for checks and to 
    // read the program header table from the file, in order to access the PT_LOAD entries
    // which enable the memory-mapping of the ELF file
    ProgramHeaders * ph = read_program_headers(fd);


    if (!ph) {
        fprintf(stderr, "error reading ELF file\n");
        free(ph->headers);
        free(ph);
        return NULL;
    }

    int num_load_segments = 0;
    // count PT_LOAD headers
    for (int i = 0; i < ph->num_headers; i++) {
        if (ph->headers[i].p_type == PT_LOAD) {
            num_load_segments++;
        } 
    }

    // create list of pointers to PT_LOAD program headers
    Elf64_Phdr ** load_segments = malloc(sizeof(Elf64_Phdr *) * num_load_segments);
    if (!load_segments) {
        perror("malloc");
        free(ph->headers);
        free(ph);
        return NULL;
    }
    int j = 0;
    for (int i = 0; i < ph->num_headers; i++) {
        if (ph->headers[i].p_type == PT_LOAD) {
            load_segments[j++] = &ph->headers[i];
        }
    }

    // mmap/load segments
    uint64_t offset = 0;
    if (num_load_segments > 0) {
        if (mmap_segments(load_segments, num_load_segments, fd, &offset) == -1) {
            fprintf(stderr, "failed to mmap segments\n");
            free(load_segments);
            free(ph->headers);
            free(ph);
            return NULL;
        }
    }
    // program header table does not necessarily contain a PT_PHDR entry (specifying the location of the program header table itself),
    // may only be present if the program header table itself is part of a PT_LOAD segment

    *map_offset = offset;  // return mapping offset
    ph->entry_point += offset;  // adjust entry point
    free(load_segments);
    return ph;
}


/**
 * @brief Performs (fast) symbol name lookup in the specified symbol table using a GNU_HASH hash table. Returns the symbol if
 * the lookup through the hash table was successful.
 * 
 * @param name 
 * @param gnu_hash_table 
 * @param strtab 
 * @param symtable 
 * @return Elf64_Sym* Pointer to the symbol with the specified name, if found in the symbol table, NULL else
 */
Elf64_Sym * lookup_symbol_module(const char * name, uint32_t * gnu_hash_table, char * strtab, Elf64_Sym * symtable) {
    // todo: if no hash table, search linearly (without versioned names)

    if (!gnu_hash_table){
        fprintf(stderr, "no gnu hashtable found\n");
        return NULL;
    }
    
    // read header
    uint32_t num_buckets = gnu_hash_table[0];
    uint32_t symoffset = gnu_hash_table[1];
    uint32_t bloom_size = gnu_hash_table[2];
    uint32_t shift2 = gnu_hash_table[3];
    uint64_t * bloom_filter = (uint64_t * ) &gnu_hash_table[4];
    uint32_t * buckets = (uint32_t *) &bloom_filter[bloom_size];
    uint32_t * chain = &buckets[num_buckets];

    // printf("num_buckets: %d, symoffset: %d, bloom_size: %d, shift2: %d\n", num_buckets, symoffset, bloom_size, shift2);

    uint32_t name_hash = gnu_hash(name);  // hash name

    uint64_t word = bloom_filter[(name_hash / 64) % bloom_size];
    uint64_t mask = (1ull << (name_hash % 64)) | (1ull << ((name_hash >> shift2) % 64));
    if ((mask & word) != mask) {
        // not in bloom filter
        return NULL;
    }

    uint32_t sym_idx = buckets[name_hash % num_buckets];

    if (sym_idx < symoffset) {
        return NULL;
    }
    // iterate over a chain
    while (1) {
        uint32_t h = chain[sym_idx - symoffset];  // the hash at the current sym_idx stored in the chain
        char * n = strtab + symtable[sym_idx].st_name;  // the name of the symbol at sym_idx
        // compare hashes except for LSB
        if ((h | 1) == (name_hash | 1)) {
            // then check name identify
            if (strcmp(n, name) == 0) {
                // found
                return &symtable[sym_idx];
            }
        }
        // LSB set signals chain end
        if (h & 1) {
            break;
        }
        sym_idx++;
    }

    return NULL;
}


/**
 * @brief  Map a file into memory according to the provided PT_LOAD segments. The mapping honors segments' align requirements, and maintains the specified 
 * relative address distance between them, resulting in a single mapping offset (difference between link and load address) for all segments. The mappings' contents are
 * read from the provided file descriptor according to the their file offsets.
 * 
 * @param segments a array of pointers to PT_LOAD program header entries that describe the segments that should be mapped into memory
 * @param num_segments the length of the 'segments' array
 * @param fd the file descriptor of the opened ELF file the provided segments pertain to.
 * @param map_offset if succesful, set to the mapping offset, i.e. the difference between the load and link (virtual memory) addresses of the segments,
 * which is identical for all mapped segments
 * @return 0 if successful, -1 else
 */
int mmap_segments(Elf64_Phdr **segments, int num_segments, int fd, uint64_t * map_offset) {
    long page_size = sysconf(_SC_PAGE_SIZE);

    // load/map PT_LOAD segments into memory
    // as we need to load all PT_LOAD segments into memory maintaining the relative distance between them (as specified by their virtual link addresses),
    // each PT_LOAD segment has to be mapped at a specific (page-aligned) address with 'MAP_FIXED'.
    // As not to overwrite/preempt any preexisting mappings, we at first reserve a contiguous big enough memory region to cover all the PT_LOAD segments,
    // the base address/placement of which is chosen by the kernel (via 'MAP_ANONYMOUS'), into which the individual PT_LOAD segments will get mmaped
    // PT_LOAD segments are ordered by ascending virtual address
    // see also: https://wiki.osdev.org/ELF_Tutorial#The_ELF_Program_Header

    // calculate total continuously covered memory region by all PT_LOAD segments

    // the link address from which on to reserve memory (= the minimum PT_LOAD segments' address, page-aligned),
    // i.e. the link address that will be mapped to the base load address
    uint64_t load_region_start = segments[0]->p_vaddr & ~(page_size - 1);  // page aligned (round down to previous page boundary)
    // the total size covered by all PT_LOAD segments (from the previously calculated start address on) (=end address of last PT_LOAD segment - start address)
    uint64_t load_region_size = (segments[num_segments - 1]->p_vaddr + segments[num_segments - 1]->p_memsz) - load_region_start;
    printf("will reserve memory from link address %#lx, size: %#lx bytes\n", load_region_start, load_region_size);

    // reserve memory (initialized to 0) at kernel-chosen address
    uint8_t *base_addr = mmap(NULL, load_region_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base_addr == MAP_FAILED) {
        perror("mmap base region");
        return -1;
    }
    // calculate the offset between the load and link addresses
    uint64_t offset = (uint64_t) base_addr - load_region_start;
    printf("reserved at %p, mapping offset: %#lx\n", base_addr, offset);

    for (int i = 0; i < num_segments; i++) {
        // as mmap requires the target address to be page-aligned and offset

        Elf64_Phdr * ph = segments[i];
        // check type
        if (ph->p_type != PT_LOAD) {
            fprintf(stderr, "trying to map a non-PT_LOAD segment\n");
            return -1;
        }
        // the address where to load the current segment to (must be page-aligned):
        // calculated from adding to the base load address the difference of the segment's page-aligned link address and the link base address
        uint64_t load_addr = (uint64_t) base_addr + ((ph->p_vaddr & ~(page_size - 1)) - load_region_start);
        // the offset into the file from where to load from (must be page-aligned, required by mmap),
        // as p_offset % page_size == p_vaddr % page_size (both are congruent modulo the page size) (both have the same 'distance' to previous page boundary),
        // one can calculate the file offset, which maps to the above calculated page-aligned p_vaddr (virtual link address), by also simply page-aligning the file offset
        uint64_t file_offset = ph->p_offset & ~(page_size - 1);
        // the length needed to be mmaped from the file: the segments file size + its offset from the previous page boundary
        uint64_t map_len = ph->p_filesz + (ph->p_offset - file_offset);

        // note: this loading implementation does not correctly work where two neighbouring PT_LOAD segments are contained on the same page,
        // as the latter segment (as its loading address is rounded down to the previous page boundary), overwrites the portion of the former segment located
        // on the same page with possibly differing protections


        printf("PT_LOAD: load_addr: %#lx (offset: %#lx), file_offset: %#lx, p_vaddr: %lx, p_offset: %#lx, p_filesz: %#lx, p_memsiz: %#lx, map_len: %#lx\n", load_addr, load_addr - (uint64_t)base_addr, file_offset, ph->p_vaddr, ph->p_offset, ph->p_filesz, ph->p_memsz, map_len);
        int prot = 0;
        if (ph->p_flags & PF_R) prot |= PROT_READ;
        if (ph->p_flags & PF_W) prot |= PROT_WRITE;
        if (ph->p_flags & PF_X) prot |= PROT_EXEC;

        // before loading the segment from file, set the whole designated memory area to the segment's intended memory protection
        // (needed as the segment's memory size may exceed its file size (e.g. through .bss) and otherwise, the exceeding memory would
        // not be covered by the subsequent mapping of the file content and would retain the restrictive PT_NONE from the initial, memory-reserving mmap)
        uint64_t segment_memory_len = ph->p_memsz + (ph->p_vaddr & (page_size -1));  // memory size + offset of p_vaddr into page
        printf("zeroing memory segment from %#lx for %#lx bytes\n", load_addr, segment_memory_len);
        uint64_t * res = mmap((void*) load_addr, segment_memory_len, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (res == MAP_FAILED) {
            perror("mmap segment zeroing failed");
            return -1;
        }

        res = mmap((void *) load_addr, map_len, prot ? prot : PROT_NONE, MAP_PRIVATE | MAP_FIXED, fd, file_offset);
        if (res == MAP_FAILED) {
            perror("mmap segment failed");
            return -1;
        }
        if ((uint64_t) res != load_addr) {
            fprintf(stderr, "mmap failed to load at specified address\n");
            return -1;
        }
    }

    // note: munmap of mappings not implemented
    *map_offset = offset;  // set offset as result
    return 0;


}

/**
 * @brief Parses the dynamic segment of a memory-mapped ELF module.
 * 
 * @param dyn Pointer to the first dynamic tag of the loaded module
 * @param offset The mapping offset of the loaded module (difference between link and actual load addresses)
 * @return DynInfo* Object containing all the parsed dynamic properties, or NULL on error
 */
DynInfo * parse_dynamic(Elf64_Dyn * dyn, uint64_t offset) {

    // count total number of tags and tags than can occur multiple times
    int num_dynsym = 0;  // without the terminating DT_NULL-tag
    int num_deps = 0;  // number of dependencies
    int num_runpath = 0;  // number of runpaths
    char * strtab = NULL;  // dynamic string table
    Elf64_Sym * symtab = NULL;  // dynamic symbol table
    uint32_t * gnu_hash = NULL;  // gnu hash table
    uint64_t flags = 0;  // DT_FLAGS value
    uint64_t flags1 = 0;  // DT_FLAGS_1 value
    char * soname = NULL;  // DT_SONAME value

    uint64_t * plt_got = NULL;  // address of .got.plt
    uint64_t plt_rel_sz = 0;  // size of .rel[a].plt
    uint64_t plt_rel = 0;  // type of relocation entries at .rel[a].plt (DT_REL[A])
    uint64_t * jmprel = NULL;  // addres of .rel[a].plt (relocations associated with plt)
    Elf64_Rel * rel = NULL;  // address of the dynamic relocation table of the REL type
    uint64_t num_rel = 0;  // number of entries in the REL relocation table
    Elf64_Rela * rela = NULL;  // address of the dynamic relocation table of the RELA type
    uint64_t num_rela = 0;  // number of entries in the RELA relocation table
    Elf64_Relr * relr = NULL;  // address of the RELR relocation table
    uint64_t num_relr = 0;  // number of words in the relr section/table

    uint64_t preinit_arr_sz = 0;
    uint64_t init_arr_sz = 0;
    uint64_t fini_arr_sz = 0;
    void * preinit_arr  = NULL;
    void * init_arr  = NULL;
    void * fini_arr  = NULL;
    void * init = NULL;
    void * fini = NULL;

    Elf64_Dyn * cur = dyn;
    while (cur->d_tag != DT_NULL) {
        num_dynsym++;
        if (cur->d_tag == DT_NEEDED) {
            num_deps++;
        }
        if (cur->d_tag == DT_RUNPATH) {
            num_runpath++;
        }
        if (cur->d_tag == DT_STRTAB) {
            strtab = offset + (char*) cur->d_un.d_ptr;
        } else if (cur->d_tag == DT_SYMTAB) {
            symtab = (Elf64_Sym*) (offset + cur->d_un.d_ptr);
        } else if (cur->d_tag == DT_GNU_HASH) {
            gnu_hash = (uint32_t*) (offset + cur->d_un.d_ptr);
        } else if (cur->d_tag == DT_FLAGS_1) {
            flags1 = cur->d_un.d_val;
        } else if (cur->d_tag == DT_FLAGS) {
            flags = cur->d_un.d_val;
        } else if (cur->d_tag == DT_PLTGOT) {
            plt_got = (uint64_t *) (offset + cur->d_un.d_ptr);
        } else if (cur->d_tag == DT_PLTRELSZ) {
            plt_rel_sz = cur->d_un.d_val;
        } else if (cur->d_tag == DT_PLTREL) {
            plt_rel = cur->d_un.d_val;
        } else if (cur->d_tag == DT_JMPREL) {
            jmprel = (uint64_t*) (offset + cur->d_un.d_ptr);
        } else if (cur->d_tag == DT_REL) {
            rel = (Elf64_Rel*) (offset + cur->d_un.d_ptr);
        } else if (cur->d_tag == DT_RELR) {
            relr = (Elf64_Relr*) (offset + cur->d_un.d_ptr);
        } else if (cur->d_tag == DT_RELA) {
            rela = (Elf64_Rela*) (offset + cur->d_un.d_ptr);
        } else if (cur->d_tag == DT_RELSZ) {
            // ignoring DT_RELENT
            num_rel = cur->d_un.d_val / 16;
        } else if (cur->d_tag == DT_RELASZ) {
            // ignoring DT_RELAENT
            num_rela = cur->d_un.d_val / 24;
        } else if (cur->d_tag == DT_RELRSZ) {
            // ignoring DT_RELRENT
            num_relr = cur->d_un.d_val / 8;
        } else if (cur->d_tag == DT_PREINIT_ARRAYSZ) {
            preinit_arr_sz = cur->d_un.d_val;
        } else if (cur->d_tag == DT_INIT_ARRAYSZ) {
            init_arr_sz = cur->d_un.d_val;
        } else if (cur->d_tag == DT_FINI_ARRAYSZ) {
            fini_arr_sz = cur->d_un.d_val;
        } else if (cur->d_tag == DT_PREINIT_ARRAY) {
            preinit_arr = (void *) (offset + cur->d_un.d_ptr);
        } else if (cur->d_tag == DT_INIT_ARRAY) {
            init_arr = (void *) (offset + cur->d_un.d_val);
        } else if (cur->d_tag == DT_FINI_ARRAY) {
            fini_arr = (void *)( offset + cur->d_un.d_val);
        } else if (cur->d_tag == DT_INIT) {
            init = (void *) (offset + cur->d_un.d_val);
        } else if (cur->d_tag == DT_FINI) {
            fini = (void *) (offset + cur->d_un.d_val);
        }
        
        cur++;
    }
    // whether ELF is a PIE or shared library
    bool is_pie = flags1 & DF_1_PIE;

    // set (dynamic) symbol table (DT_SYMTAB) and string table (DT_STRTAB)
    // as mandatory (for simplification)
    if (!strtab) {
        fprintf(stderr, "missing string table\n");
        return NULL;
    }
    if (!symtab) {
        fprintf(stderr, "missing symbol table\n");
        return NULL;
    }

    // GNU hash table is mandatory for shared libraries modules
    // legacy hash table is not supported
    if (!is_pie) {
        if (!gnu_hash) {
            fprintf(stderr, "missing GNU_HASH\n");
            return NULL;
        }
    }

    // if we have any plt-associated relocations (.rel[a].plt),
    // check related tags for consistency
    if (jmprel) {
        // .got.plt must also be present
        if (!plt_got) {
            fprintf(stderr, "missing DT_PLTGOT\n");
            return NULL;
        }
        // note: DT_PLTRELSZ might legitimately be size 0

        if (!(plt_rel == DT_REL || plt_rel == DT_RELA)) {
            fprintf(stderr, "uknown PLT relocation type (%ld)\n", plt_rel);
            return NULL;
        }
    }


    // list of dynamically-allocated strings of the resolved dependencies' names
    char **dependencies = malloc(num_deps * sizeof(char *));
    char **runpaths = malloc(num_runpath * sizeof(char *));

    int k = 0;
    for (size_t i = 0; i < num_dynsym; i++) {
        Elf64_Dyn * c = &dyn[i];
        // collect all runpaths
        if (c->d_tag == DT_RUNPATH) {
            // pointer to runpath string in string table
            runpaths[k++] = strtab + c->d_un.d_val;
        } else if (c->d_tag == DT_SONAME) {
            soname = strtab + c->d_un.d_val;
        }
    }

    // dependency resolution
    // DT_RPATH not supported, only DT_RUNPATH (not transitive)
    int j = 0;
    for (size_t i = 0; i < num_dynsym; i++) {
        Elf64_Dyn * c = &dyn[i];
        if (c->d_tag == DT_NEEDED) {
            // pointer to dependency name string in string table
            char * dep_name = strtab + c->d_un.d_val;
            printf("DT_NEEDED: %s\n", dep_name);
            // resolve dependency name
            char * resolved_name = resolve_name(dep_name, runpaths, num_runpath);
            if (resolved_name) {
                printf("resolved to: %s\n", resolved_name);
                dependencies[j++] = resolved_name;
            } else {
                fprintf(stderr, "could not resolve '%s'\n", dep_name);
                return NULL;
            }
        }
    }

    DynInfo * dyn_info = malloc(sizeof(DynInfo));
    if (!dyn_info) {
        perror("malloc");
        free(runpaths);
        return NULL;
    }
    // set fields
    dyn_info->dependencies = dependencies;
    dyn_info->num_dependencies = num_deps;
    dyn_info->flags = flags;
    dyn_info->flags1 = flags1;
    dyn_info->strtab = strtab;
    dyn_info->symtab = symtab;
    dyn_info->soname = soname;
    dyn_info->gnu_hash = gnu_hash;
    dyn_info->plt_got = plt_got;
    dyn_info->plt_rel_sz = plt_rel_sz;
    dyn_info->plt_rel = plt_rel;
    dyn_info->jmprel = jmprel;
    dyn_info->rel = rel;
    dyn_info->rela = rela;
    dyn_info->relr = relr;
    dyn_info->num_rel = num_rel;
    dyn_info->num_rela = num_rela;
    dyn_info->num_relr = num_relr;
    dyn_info->preinit_arr_sz = preinit_arr_sz;
    dyn_info->init_arr_sz = init_arr_sz;
    dyn_info->fini_arr_sz = fini_arr_sz;
    dyn_info->preinit_arr = preinit_arr;
    dyn_info->init_arr = init_arr;
    dyn_info->fini_arr = fini_arr;
    dyn_info->init = init;
    dyn_info->fini = fini;


    free(runpaths);
    return dyn_info;
}

ElfModule * _find_loaded_dependency(char * path, ElfModule * m, bool visited[]) {
    // DFS
    ElfModule * res = NULL;
    visited[m->module_id] = 1;  // mark as visited
    for (size_t i = 0; i < m->num_dependencies; i++) {
            ElfModule * d = m->dependencies[i];
            if(d) {
                if (!visited[d->module_id]) {
                    res = _find_loaded_dependency(path, d, visited);
                    if(res) {
                        return res;
                    }
                }
            }
        }
    // check path
    if (strcmp(path, m->path) == 0) {
        // found
        free(visited);
        return m;
    }
    return NULL;
}

// find if dependency has already been loaded
ElfModule * find_loaded_dependency(char * path, ElfLoaderCtx * ctx) {
    if (!ctx->root) {
        return NULL;
    }
    ElfModule * res = NULL;
    bool *visited = calloc(ctx->num_modules, sizeof(bool));
    res = _find_loaded_dependency(path, ctx->root, visited);

    free(visited);
    return res;
}

void _free_module_tree(ElfModule * m, bool visited[]) {
    visited[m->module_id] = 1;  // mark self as visited
    for (size_t i = 0; i < m->num_dependencies; i++) {
        _free_module_tree(m->dependencies[i], visited);
    }
    if (m->dependencies) {
        free(m->dependencies);
    }
    if (m->tls_info) {
        free(m->tls_info);
    }
    
    free(m);
}

void free_module_tree(ElfLoaderCtx * ctx) {
    if (!ctx->root) {
        return;
    }
    bool *visited = calloc(ctx->num_modules, sizeof(bool));
    _free_module_tree(ctx->root, visited);
    free(visited);
}


/**
 * @brief Loads the specified ELF module from file into memory (its loadable segments) and recursively (BFS) resolves and loads all of its dependencies (DT_NEEDED).
 * Constructs or updates a dependency graph representing all loaded modules, provided by the ctx object.
 * Returns an object representing the properties of the parsed and loaded module.
 * 
 * Before loading, the already existing dependency graph is searched for a module loaded from the same path, which is returned if found,
 * to prevent duplication. If the dependency graph is not yet existent (NULL root), the loaded module must be a position-independent executable and
 * will become the new root. The returned object (and all of its dynamically allocated members) must be freed.
 * 
 * @param file_path A path to the ELF file to be loaded
 * @param ctx Pointer to an ElfLoaderCtx object for constructing and accessing the dependency tree
 * @return ElfModule* A pointer to the dynamically allocated object representing the loaded module, or NULL in case of an error.
 */
ElfModule * load_module(char* file_path, ElfLoaderCtx * ctx) {
    printf("loading module '%s'\n", file_path);
    // check if module has already been loaded
    ElfModule * existing = find_loaded_dependency(file_path, ctx);
    if (existing) {
        printf("module has already been loaded (id: %d)\n", existing->module_id);
        return existing;
    }

    // open file
    int fd = open(file_path, O_RDONLY, "rb");
    if (fd == -1) {
        perror("open module");
        return NULL;
    }
    uint64_t map_offset = 0;
    // map into memory (PT_LOAD segments) and get (separately allocated) all program headers
    ProgramHeaders * ph = load_elf(fd, &map_offset);
    if (!ph) {
        fprintf(stderr, "error mapping ELF file\n");
        close(fd);
    }

    // read PT_DYNAMIC, PT_INTERP and PT_TLS
    Elf64_Dyn * dynamic = NULL;
    char * interp = NULL;
    TLS_Block_t * tls_info = NULL;
    for (int i = 0; i < ph->num_headers; i++) {
        Elf64_Phdr * p = &ph->headers[i];
        if (p->p_type == PT_DYNAMIC) {
            dynamic = (Elf64_Dyn *) (p->p_vaddr + map_offset);
        } else if (p->p_type == PT_INTERP) {
            interp = (char*) (p->p_vaddr + map_offset);
        } else if (p->p_type == PT_TLS) {
            // the TLS entry, if it exists
            tls_info = malloc(sizeof(TLS_Block_t));
            // save values
            tls_info->start = p->p_vaddr;
            tls_info->align = p->p_align;
            tls_info->memsz = p->p_memsz;
            tls_info->filesz = p->p_filesz;
        }
        
        // ignoring PT_GNU_STACK, PT_GNU_RELRO etc for now
    }
    if (!dynamic) {
        fprintf(stderr, "missing PT_DYNAMIC segment\n");
        free(ph->headers);
        free(ph);
        free(tls_info);
        close(fd);
        return NULL;
    }

    // parse dynamic segment
    DynInfo * dyn_info = parse_dynamic(dynamic, map_offset);
    if (!dyn_info) {
        fprintf(stderr, "error parsing dynamic segment\n");
        free(ph->headers);
        free(ph);
        free(tls_info);
        close(fd);
        return NULL;
    }

    // interpreter path (PT_INTERP) is mandatory for PIEs
    if (dyn_info->flags1 & DF_1_PIE && !interp){
        fprintf(stderr, "missing PT_INTERP for PIE\n");
        free_dyn_info(dyn_info);
        free(dyn_info);
        free(ph->headers);
        free(ph);
        free(tls_info);
        close(fd);
        return NULL;
    }
    
    printf("new module: symtable: %p, strtab: %p, %d dependencies, so_name: %s\n",
        dyn_info->symtab, dyn_info->strtab, dyn_info->num_dependencies, dyn_info->soname);

    // Remove duplicates dependencies
    deduplicate_deps(dyn_info);

    for (size_t i = 0; i < dyn_info->num_dependencies; i++) {
        printf("dep: %s\n", dyn_info->dependencies[i]);
    }
    

    // create new module
    ElfModule *m = malloc(sizeof(ElfModule));
    m->ctx = ctx;
    m->dependencies = calloc(dyn_info->num_dependencies, sizeof(ElfModule*));
    m->module_id = ctx->num_modules++;  // assign next module number
    m->flags = dyn_info->flags;
    m->flags1 = dyn_info->flags1;
    m->map_offset = map_offset;
    m->entry_point = (void *)ph->entry_point;
    m->dynamic = dynamic;
    m->soname = dyn_info->soname;
    m->gnu_hash = dyn_info->gnu_hash;
    m->path = file_path;
    m->interp = interp;
    m->strtab = dyn_info->strtab;
    m->symtab = dyn_info->symtab;
    m->num_dependencies = dyn_info->num_dependencies;
    m->plt_got = dyn_info->plt_got;
    m->plt_rel_sz = dyn_info->plt_rel_sz;
    m->plt_rel = dyn_info->plt_rel;
    m->rel = dyn_info->rel;
    m->num_rel = dyn_info->num_rel;
    m->rela = dyn_info->rela;
    m->num_rela = dyn_info->num_rela;
    m->relr = dyn_info->relr;
    m->num_relr = dyn_info->num_relr;
    m->tls_info = tls_info;
    if (m->tls_info) {
        // add backreference to module itself
        m->tls_info->m = m;
    }
    m->preinit_arr_sz = dyn_info->preinit_arr_sz;
    m->init_arr_sz = dyn_info->init_arr_sz;
    m->fini_arr_sz = dyn_info->fini_arr_sz;
    m->preinit_arr = dyn_info->preinit_arr;
    m->init_arr = dyn_info->init_arr;
    m->fini_arr = dyn_info->fini_arr;
    m->init = dyn_info->init;
    m->fini = dyn_info->fini;
    printf("module id: %d, map offset: %#lx\n", m->module_id, m->map_offset);
    

    // if module has PLT and related relocations/got
    if (dyn_info->jmprel) {
        if (m->plt_rel == DT_REL) {
            m->jmprel.rel = (Elf64_Rel *) dyn_info->jmprel;
        } else if (m->plt_rel == DT_RELA) {
            m->jmprel.rela = (Elf64_Rela *) dyn_info->jmprel;
        } else {
            fprintf(stderr, "uknown PLT relocation type (%ld)\n", m->plt_rel);
            free(m->dependencies);
            free(m);
            free(tls_info);
            m = NULL;
            goto load_module_exit;
        }
        printf(".got.plt: %p, .rel[a].plt: %p (size %#lx, type: %s)\n", m->plt_got, m->jmprel.rel, m->plt_rel_sz,
            m->plt_rel == DT_RELA ? "RELA":"REL");
        int plt_rel_ent = m->plt_rel == DT_RELA ? 24 : 16;  // .rel[a].plt entry size
        prepare_got_plt(m->plt_got, m->map_offset, m, (m->plt_rel_sz / plt_rel_ent) + 3);  // account for the initial 3 reserved .got.plt slots
    }

    if (!ctx->root) {
        // root not yet set, this module will become new root
        if (!(dyn_info->flags1 & DF_1_PIE)) {
            // only PIEs allowed as root program
            fprintf(stderr, "root module must be a position-independent executable\n");
            free(m->dependencies);
            free(m);
            free(tls_info);
            m = NULL;
            goto load_module_exit;
        }
        ctx->root = m;
    }

    // load dependencies
    for (size_t i = 0; i < dyn_info->num_dependencies; i++) {
        ElfModule *d = load_module(dyn_info->dependencies[i], ctx);
        if (!d) {
            fprintf(stderr, "error loading module '%s'\n", dyn_info->dependencies[i]);
            free(m->dependencies);
            free(m);
            free(tls_info);
            m = NULL;
            goto load_module_exit;
        }
        m->dependencies[i] = d;  // insert new edge in dependency graph
    }

load_module_exit:
    free_dyn_info(dyn_info);
    free(dyn_info);
    free(ph->headers);
    free(ph);
    close(fd);
    return m;
}

// callback to create pointer to a module's TLS block, if existent
int collect_tls_blocks(ElfModule * m, void *b) {
    TLS_Block_t ** blocks = (TLS_Block_t **) b;
    // printf("module %d: %p\n", m->module_id, m->tls_info);
    if (m->tls_info) {
        blocks[m->module_id] = m->tls_info;
    }
    return 0;
}

/**
 * @brief Constructs a static TLS (Thread-Local Storage) image from all loaded modules' PT_TLS segments.
 *
 * This function scans all loaded modules for PT_TLS segments (static TLS set), copies their contents into a single
 * contiguous memory block (TLS image/region), and constructs the accompanying dynamic thread vector (dtv). The resulting
 * TLS_t structure encapsulates both the TLS data and its metadata, making it suitable for use as the
 * thread-local storage for the main thread. If support for threading (creation of threads) would be required, the new thread
 * would need to receive a copy of the initial TLS image. Does only support static TLS (TLS segments of all loaded modules) and no
 * dynamic segment (modules loaded dynamically/later via dlopen).
 * See:
 *  - https://fuchsia.dev/fuchsia-src/development/kernel/threads/tls
 *  - https://maskray.me/blog/2021-02-14-all-about-thread-local-storage
 *  - https://chao-tic.github.io/blog/2018/12/25/tls
 *  - https://uclibc.org/docs/tls.pdf
 *  - https://www.fsfla.org/~lxoliva/writeups/TLS/paper-lk2006.pdf
 *  - https://android.googlesource.com/platform/bionic/+/HEAD/docs/elf-tls.md
 *  - https://wiki.musl-libc.org/design-concepts#Thread-local-storage
 *  - https://github.com/gcc-mirror/gcc/blob/32b8d1312382e3f179df4f76eca840486d6608e8/gcc/config/aarch64/aarch64.cc#L3115-L3140
 *
 * @note The returned TLS_t structure is dynamically allocated and must be freed by the caller to avoid memory leaks.
 *
 * @return Pointer to the newly created TLS_t structure.
 */
TLS_t * setup_tls(ElfLoaderCtx * ctx) {

    // collect (pointers to) all loaded modules' TLS segments/blocks
    TLS_Block_t ** blocks = calloc(ctx->num_modules, sizeof(TLS_Block_t *));
    visit_dfs(ctx, collect_tls_blocks, (void *) blocks);

    // to create the TLS image (all TLS segments concatenated), first calculate
    // the required size (with correct alignment paddings)

    // the offset of every module's TLS block (indexed by module id) into the TLS image
    int * offsets = calloc(ctx->num_modules, sizeof(int));
    int pos = sizeof(TLS_t);  // start at the TLS data structures fixed-sized header (16 bytes)
    for (size_t i = 0; i < ctx->num_modules; i++) {
        TLS_Block_t * t = blocks[i];
        if (t) {
            // add required padding
            pos += (t->align - (pos % t->align)) % t->align;
            offsets[i] = pos;  // record position
            pos += t->memsz;  // advance position
            
        }
    }
    // allocate memory for TLS data structure (with memory for TLS image)
    TLS_t * d = malloc(sizeof(TLS_t) + pos);
    // copy the TLS segments into their position in the resulting TLS image
    for (size_t i = 0; i < ctx->num_modules; i++) {
        TLS_Block_t * b = blocks[i];
        if (b) {
            ElfModule *m = b->m;
            // copy in TLS block from loaded module
            memcpy(&d->data[offsets[i]], (void *)(m->map_offset + b->start), b->filesz);
        }
    }
    // create dynamic thread vector (dtv, contains for every module a pointer to its TLS block)
    d->dtv = calloc(ctx->num_modules, sizeof(uint8_t *));
    for (size_t i = 0; i < ctx->num_modules; i++){
        TLS_Block_t * t = blocks[i];
        if (t) {
            d->dtv[i] = &d->data[offsets[i]];
        }
    }
    free(blocks);
    free(offsets);
    return d;
}


/**
 * @brief Allocate and setup a stack suitable for program execution with auxiliary vectors, environment variables, command line arguments,
 * as expected by e.g. __libc_start_main() on Aarch64. The new stack pointer points to the argc variable, which is followed by pointers to the argv strings,
 * followed by a NULL pointer and the envp (environment variable strings) pointers (again delimited by a NULL pointer). 
 * 
 * @return The pointer to the new stack, or NULL if memory could not be allocated
 */
void * setup_stack() {
    // stack layout:
    // https://articles.manugarg.com/aboutelfauxiliaryvectors
    // https://aeb.win.tue.nl/linux/hh/stack-layout.html
    // https://refspecs.linuxfoundation.org/LSB_1.3.0/IA64/spec/auxiliaryvector.html
    // https://lwn.net/Articles/519085/
    // https://lwn.net/Articles/631631/


    uint64_t stack_alloc_size = 0x800000;  // some default size
    // allocate stack via mmap with fixed stack size, throws SIGSEV if stack is exceeded
    // don't use MAP_GROWSDOWN, as it's unreliable and not advised to use
    // https://stackoverflow.com/a/56920770
    // https://stackoverflow.com/a/56921143

    // allocate (mmap) stack memory
    // returns start of mmapped memory (=max stack address/stack top)
    void *new_stack = mmap(NULL, stack_alloc_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (new_stack == MAP_FAILED) {
        perror("mmap stack");
        return NULL;
    }
    void *stack_bottom = new_stack + stack_alloc_size;  // end of mmapped memory (=stack bottom)

    // the used auxilliary vector with some default values (read from auxiliary values provided to this loader program itself)
    Elf64_auxv_t auxv[] = {
        {.a_type = AT_HWCAP, .a_un.a_val = getauxval(AT_HWCAP)},
        {.a_type = AT_HWCAP2, .a_un.a_val = getauxval(AT_HWCAP2)},
        {.a_type = AT_PAGESZ, .a_un.a_val = getauxval(AT_PAGESZ)},
        {.a_type = AT_PLATFORM, .a_un.a_val = getauxval(AT_PLATFORM)},
        {.a_type = AT_FPUCW, .a_un.a_val = getauxval(AT_FPUCW)},
        {.a_type = AT_NULL, .a_un.a_val = 0}
    };

    // the program args (argv elements)
    char * args[] = {"./loader_demo"};  // argv[0] should be the program name, hardcoded for simplification
    int argc = sizeof(args) / sizeof(char*);
    // environment variables (will become envp pointers) for demonstration
    char * envs[] = {"USER=pi", "SHELL=/bin/bash", "PWD=/home/pi/"};
    int envc = sizeof(envs) / sizeof(char*);
    int auxc = sizeof(auxv) / sizeof(Elf64_auxv_t);

    // calculate concatenated size of strings, which will be located at the bottom of the stack
    int var_sz = 0;  // the total 'variable' elements' size (mostly strings)
    for (size_t i = 0; i < argc; i++) {
        var_sz += strlen(args[i]) + 1;  // account for \0
    }
    for (size_t i = 0; i < envc; i++) {
        var_sz += strlen(envs[i]) + 1;
    }

    // fixed-size stack contents size (mostly pointers) (account for NULL sentinels at end of argv/envp + argc itself)
    // argc is also 8-bytes (uint64_t), so that the following argv pointers are 8-aligned
    int fixed_sz = sizeof(uint64_t) + (argc + 1 + envc + 1) * sizeof(char*) + sizeof(auxv);
    // calculate padding so that resulting new stack pointer (top of stack) is 16-aligned
    int pad_len = (16 - (fixed_sz + var_sz) % 16) % 16;

    int stack_size = fixed_sz + var_sz + pad_len;  // initial stack size (with argc/v, envp, auxv)
    void * sp = stack_bottom - stack_size;  // new stack pointer
    memset(sp, 0, stack_size);  // init to 0

    // set argc (at sp[0])
    *(uint64_t*) sp = argc;

    // copy in the argv/envp strings and fill in pointers to them
    char ** f_ptr = (char**)(sp + sizeof(uint64_t));  // pointer to char pointer entries (argv+envp), start at sp[1]
    char * var_ptr = stack_bottom - var_sz;  // current pointer for storing the next string, start at pre-determined position
    for (size_t i = 0; i < argc; i++) {
        size_t s = strlen(args[i]) + 1;
        memcpy(var_ptr, args[i], s);  // copy argv string itself
        *f_ptr++ = var_ptr;  // set pointer to string
        var_ptr += s;
    }
    f_ptr++;  // NULL terminator
    for (size_t i = 0; i < envc; i++){
        size_t s = strlen(envs[i]) + 1;
        memcpy(var_ptr, envs[i], s);
        *f_ptr++ = var_ptr;
        var_ptr += s;
    }
    f_ptr++;  // NULL terminator
    memcpy(f_ptr, auxv, sizeof(auxv));  // copy in auxv


    printf("argc: %d, envc: %d, auxc: %d, strings len: %d, fixed sz: %d, var sz: %d, padding: %d, stack size: %d, new stack: %p, stack top: %p, sp: %p\n", argc, envc, auxc, var_sz, fixed_sz, var_sz, pad_len, stack_size, new_stack, stack_bottom, sp);

    // munmap(new_stack, stack_alloc_size);  // get's unmapped at process exit
    return sp;
}

/**
 * @brief Switch the used stack to the provided one, execute the given function and restore the environment (stack). Intended for execution of
 * initialization/finalization functions
 * 
 * @param stack The stack pointer to which to temporarily switch to and execute the given function on
 * @param func The function to execute on the stack, conforming to the following prototype: void func(void)
 */
void run_with_stack(void * stack, void (*func)(void)) {
    // When switching to the new stack in order to execute a function, the current stack pointer and return address
    // need to be saved in order to properly restore them after the called function has returned
    // this could either happen on the new stack, as the need to be restorable from said new stack (difficult, as it would need to be placed under the conventionally setup
    // stack arguments (args/envp, etc), at a compile-time constant offset (required by the inline asm 'stp' instruction)),
    // or, much simpler, be stored in callee-saved registers, specified explicitly (https://gcc.gnu.org/onlinedocs/gcc/Explicit-Register-Variables.html)

    // see for inline asm:
    // https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html
    // https://gcc.gnu.org/onlinedocs/gcc/Constraints.html
    // https://gcc.gnu.org/onlinedocs/gcc/Machine-Constraints.html

    // reserve explicitly callee-saved registers as scratch
    register int64_t *old_sp asm("x20");
    register int64_t *old_lr asm("x21");

    asm volatile(
        // save original sp, lr to callee-saved registers
        "mov %[old_sp], sp\n"
        "mov %[old_lr], lr\n"
        // switch to new stack
        "mov sp, %[new_sp]\n"

        // call function
        "blr %[func]\n"
        // restore original sp, lr
        "mov sp, %[old_sp]\n"
        "mov lr, %[old_lr]\n"
        :
        :[new_sp]"r"(stack), [old_sp]"r"(old_sp), [old_lr]"r"(old_lr),[func]"r"(func)
        :"x30"
    );

}



/* Normally, the linker/loader calls/transfers control to the address of the main executable's entrypoint (a field in the ELF header),
usually designated by the symbol _start, which in turn should call (for glibc-linked executables) __libc_start_main().
This function performs the initialization of all necessary data structures, glibc-proprietary data/environment, calls main() and
subsequently handles the return code, calls finalization routines and terminates the process with the exit syscall().
The prototype is as follows: __libc_start_main(int *(main) (int, char * *, char * *), int argc, char * * ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end)),
where (on current glibc for Aarch64) (https://refspecs.linuxbase.org/LSB_3.1.0/LSB-generic/LSB-generic/baselib---libc-start-main-.html):
 - main is a pointer to the main() entry point
 - argc is the number of arguments (same as argc for main())
 - ubp_av are (unbounded) argv (argument) pointers (argv for main())
 - init and fini are pointers to initialization/finalization routines, ununsed and set to NULL
 - rtld_fini is a finalization function to be run at process exit (for .fini/destructors)
 - stack_end is a pointer designating the stacks bottom (exact usage is unclear)

The _start function expects by convention the rtld_fini function pointer in x0, and expects a validly setup stack,
with argc on the top (pointed to by the stack pointer) and has the following usual sequence to setup the arguments for __libc_start_main():
mov     x29, #0x0  // clear lr and fp, starting a new stack
mov     x30, #0x0
mov     x5, x0  // copy *rtld__fini pointer to x5
ldr     x1, [sp]  // load argc into x1
add     x2, sp, #0x8  // load &argv into x2 (8 bytes (directly) on the stack under argc)
mov     x6, sp  // stack_end to x6
adrp    x0, 1f000 <__FRAME_END__+0x1e758>  // load address of main() into x0
ldr     x0, [x0, #4056]
mov     x3, #0x0   // init, fini unused
mov     x4, #0x0
bl      5f0 <__libc_start_main@plt>  // actual call
bl      630 <abort@plt>  // should never be executed, __libc_start_main does not return (but exit the process at the end)
(see also: https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/aarch64/start.S;h=694c338c8be3f6ab642e88f84eeec804d6946580;hb=HEAD)

The dynamic linker would setup the stack and branch to _start (using an unconditional jump (br), as it never returns), where in turn
__libc_start_main() would then initialize (including TLS/thread handling) the environment, execute the main() function, run finalization routines (rtld_fini)
and finally exit the process, so the loader will never regain control.
see: https://sourceware.org/git/?p=glibc.git;a=blob;f=csu/libc-start.c#l234
https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/aarch64/dl-start.S;h=2ccc219f1efe81e04379f148c86bf7c5a59c3353;hb=HEAD
https://blog.k3170makan.com/2018/10/introduction-to-elf-format-part-v.html

Because the __libc_start_main implementation (part of the used c runtime) usually depends on the libc (c standard library) the executable
was compiled/linked with and is typically tightly coupled with the dynamic linker (ld-linux-*.so for glibc, ld-musl-*.so for musl) using/sharing internal function/data structures
(e.g. 'rtld_global', a glibc global data structure for loaded objects/tls, or link maps for loaded modules), we would need to setup/replicate those internals exactly as __libc_start_main expects them to be,
rendering this approach impracticable for a custom dynamic linker (in short: the dynamic linker and standard library share an interal API).

Therefore, as we have already setup the stack, the TLS image (for the main thread), called initializers, which would normally be accomplished by the c runtime (all initiated and managed by __libc_start_main),
we call the main() directly (mimicking said c runtime) ourselves (and handling the return value, cleanup). This approach only works for simple programs, does not support the libc-specific
threading implementation, and might not work with (g)libc functions that need a certain state (e.g. TLS related variable access).
*/

/**
 * @brief Switches to the stack (which must be properly setup) and the thread pointer provided by the context,
 * executes the provided main function, restores the environment and returns the returned value.
 * 
 * @param ctx The context providing the used stack and thread pointer.
 * @param main_func The function conforming to the main()-prototype (main(int argc, char **argv, char **envp)), that will be executed in the given environment
 * @return int The value returned by the main function
 * 
 */
int call_main(ElfLoaderCtx * ctx, void * main_func) {

    // current sp and lr need to be preserved (in callee-saved registers) so that the state can be restored (switched back)
    // after the function returns
    register int64_t *old_sp asm("x20");
    register int64_t *old_lr asm("x21");
    register int64_t *old_tp asm("x22");
    int64_t ret;

    asm volatile(
        // save original sp, lr, tp
        "mov %[old_sp], sp\n"
        "mov %[old_lr], lr\n"
        "mrs %[old_tp], tpidr_el0\n"
        // switch to new stack
        "mov sp, %[new_sp]\n"
        // switch to new thread pointer
        "msr tpidr_el0, %[new_tp]\n"
        // setup arguments for main() 
        "ldr x0, [sp]\n"  // x0: argc
        "add x1, sp, #8\n"  // x1:argv
        // x2: envp
        // calculate position of envp (environment variables pointer array),
        // located on the stack under the last argv pointer and following NULL separator
        "add x2, sp, x0, LSL 3\n"  // length of argv in bytes
        "add x2, x2, #16\n"  // acount for argc (top of stack, 8 bytes) and the NULL separator

        // call function
        "blr %[func]\n"
        // restore original sp, lr, tp
        "mov sp, %[old_sp]\n"
        "mov lr, %[old_lr]\n"
        "msr tpidr_el0, %[old_tp]\n"
        "mov %[ret], x0\n"
        :[ret]"=r"(ret)
        :[new_sp]"r"(ctx->stack), [new_tp]"r"(ctx->tls), [old_sp]"r"(old_sp), [old_lr]"r"(old_lr), [old_tp]"r"(old_tp), [func]"r"(main_func)
        :"x30", "x0", "x1", "x2"
    );
    return (int) ret;
}


// run initialization for a module
int init_module(ElfModule *m, void * stack) {
    // run DT_INIT before DT_INIT_ARRAY
    if (m->init) {
        run_with_stack(stack, (void (*)(void))m->init);
    }
    if (m->init_arr) {
        int num_func = m->init_arr_sz / sizeof(void *);
        void (**f)(void) = (void (**)(void)) m->init_arr;
        // glibc convention: first entry of DT_INIT_ARRAY is skipped:
        // https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/dl-init.c#l72
        for (size_t i = 1; i < num_func; i++) {
            run_with_stack(stack, f[i]);
        }
        
    }
    return 0;
}

// run finalization for a module
int fini_module(ElfModule *m, void * stack) {
    // DT_FINI_ARRAY before DT_FINI
    if (m->fini_arr) {
        int num_func = m->fini_arr_sz / sizeof(void *);
        void (**f)(void) = (void (**)(void)) m->init_arr;
        // reversed order, skip entry at index 0
        for (int i = num_func; i-- < 1;) {
            run_with_stack(stack, f[i]);
        }
    }
    if (m->fini) {
        run_with_stack(stack, (void (*)(void))m->fini);
    }
    return 0;
}


int main(int argc, char **argv) {
    int return_code = 0;
    if (argc < 3) {
        fprintf(stderr, "usage: %s <elf-file> <main-addr (hex)>\n", argv[0]);
        return 1;
    }
    unsigned long main_offset = strtoul(argv[2], NULL, 16);
    if (!main_offset) {
        fprintf(stderr, "invalid main offset\n");
        return 1;
    }
    

    ElfLoaderCtx ctx = {.num_modules = 0, .root = NULL};  // create context
    // used for IFUNCs, see Aarch64 SysV Abi
    ctx.at_hwcap = getauxval(AT_HWCAP);
    ctx.at_hwcap |= _IFUNC_ARG_HWCAP;  // signal that second parameter (of type '__ifunc_arg_t') is passed to ifunc resolvers
    ctx.hwcap_struct._size = 24;
    ctx.hwcap_struct._hwcap = getauxval(AT_HWCAP);
    ctx.hwcap_struct._hwcap2 = getauxval(AT_HWCAP2);

    load_module(argv[1], &ctx);  // load module with its dependencies

    ctx.tls = setup_tls(&ctx);  // create TLS image

    
    // relocations must be processed in dfs-fashion, i.e. all dependencies' relocations must be processed before the dependent's
    visit_dfs(&ctx, process_relocs, NULL);  // resolve relocations


    visit_dfs(&ctx, module_handle_plt, NULL);  // eagerly resolve PLT relocations if indicated by the module's flags

    ctx.stack = setup_stack();  // create stack

    // initialization/finalization routines/sections:
    // https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcobks/index.html
    // https://docs.oracle.com/cd/E19683-01/816-1386/6m7qcobkh/index.html#chapter2-48195
    // pre-initialization: only on the executable module
    if (ctx.root->preinit_arr) {
        printf("running pre-initialization\n");
        int num_func = ctx.root->preinit_arr_sz / sizeof(void *);
        void (**f)(void) = (void (**)(void)) ctx.root->preinit_arr;
        // glibc convention: skip first entry
        for (size_t i = 1; i < num_func; i++) {
            run_with_stack(ctx.stack, f[i]);
        }
    }

    // initialization: dependencies's before module's initialization routines
    printf("running initialization\n");
    visit_dfs(&ctx, init_module, ctx.stack);


    void * entry_point_func = (void*) (ctx.root->map_offset + main_offset);
    printf("calling main()\n");
    // transfer control to executable's entry point
    return_code = call_main(&ctx, entry_point_func);
    printf("return value: %d\n", return_code);

    // finalization: module's finalization before its dependencies'
    printf("running finalization\n");
    visit_dfs_reverse(&ctx, fini_module, ctx.stack);

// exit:
    free_module_tree(&ctx);
    if (ctx.tls) {
        free(ctx.tls->dtv);
        free(ctx.tls);
    }
    
    return return_code;
}
