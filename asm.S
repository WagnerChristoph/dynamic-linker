.arch armv8-a
.extern plt_resolve
.text
.global dl_asm_resolve
.type dl_asm_resolve, %function

// This asm veneer/shim is intended to be branched to directly as PLT resolver entrypoint for lazy PLT function resolution.
// The address (adjusted to the load address) of this function/label must be placed initially in all .got.plt entries, so that the function call to any
// PLT entry is directed to this function/label.
// Implementation must be in assembly, as this function/label is not linked to, but only branched to (no return address, is stored at sp+8),
// and because the stack must be unwound in a specific way.
// This veneer gathers the necessary information (address of the requested .got.plt entry, adress of the .got.plt[2] entry, which allows access to the private
// information word at .got.plt[1]) and calls a c-implemented resolution routine, the return value of which (the address of the resolved function) is finally
// branched to, and its return value is returned to the original caller.
// Note: As this function/lable is branched to intended as a function call (of a PLT-contained function), x0-x7 may already contain the arguments for the original,
// to-be-resolved function, so they need to be restored before calling the resolved function.
dl_asm_resolve:
    // calling convention:
    // x16: address of the resolver entry point (&.got.plt[2]) (needed to access the private information stored at .got.plt[1])
    // x17: resolver entry point
    // sp: address of the .got.plt entry to be resolved (the entry's index can be calculated by subtracting the .got.plt base address)
    // sp+8: lr

    // temporarily backup the address of .got.plt[2]
    mov x17, x16
    // restore the address of the .got.plt entry (x16) and lr from the stack (unwind the stack)
    ldp x16, x30, [sp], #16 

    // normal function prologue
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
    // backup caller-saved registers x0/x1 (will be used for arguments, but may already contain arguments for the originally intended 
    // (that led to this plt lookup) function)
    stp x0, x1, [sp, #16]

    // setup arguments for the plt lookup/resolve function
    mov x0, x17  // address of the resolver entry point/.got.plt[2]
    mov x1, x16  // address of the to-be-resolved .got.plt entry

    bl plt_resolve  // call the resolution function, returns value in x0

    mov x17, x0  // move result (address of the resolved function) to a intra-procedure-call corruptible register
    // restore arguments for the original function
    ldp x0, x1, [sp, #16]

    // call the resolved function
    blr x17

    // normal function epilogue
    ldp     x29, x30, [sp], 32
    ret

