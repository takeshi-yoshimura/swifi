/*
 * swifi.c -- fault injection code for linux
 *
 * Copyright (c) 2013 Takeshi Yoshimura
 * Copyright (C) 2003 Mike Swift
 * Copyright (c) 1999 Wee Teck Ng
 *
 * The source code in this file can be freely used, adapted,
 * and redistributed in source or binary form, so long as an
 * acknowledgment appears in derived source files.  No warranty 
 * is attached; we cannot take responsibility for errors or 
 * fitness for use.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>   //kallsyms_lookup, kallsyms_lookup_name
#include <linux/syscalls.h>   //SYSCALL_DEFINE macro
#include <asm/pgalloc.h>      //pte_write
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm/sections.h>
#include <linux/slab.h>
#include <asm/types.h>
#include "dis-asm.h"
#include "swifi.h"

#if defined(CONFIG_X86)
static const u8 NOP = 0x90;
#endif

static unsigned long tstart = (unsigned long)_stext;
static unsigned long tend = (unsigned long)_etext;

/* functions for getting a random integer with LCGs */

extern void srand(unsigned long seed);
extern unsigned long rand(void);

static unsigned long rand_range(unsigned long start, unsigned long end) 
{
    unsigned long range = end - start - sizeof(unsigned long);

    if(end <= start + sizeof(u128))
        return 0;
    return rand() % range + start;
}

static unsigned long get_random_text_addr(void)
{
    unsigned long target = 0;
    int i;

    while(tstart > target || target >= tend) {
        target = rand_range(tstart,tend) - 2 * 10;
        if (target < tstart)
            target = tstart;
        for(i = 0; i < 10; i++)
            target += do_disasm(target, NULL);
    }
    return target;
}

static unsigned long get_random_stack_addr(void)
{
    struct task_struct * task = NULL;
    int i = 0;

    for_each_process(task) {
        i++;
    }

    i = rand() % i;

    for_each_process(task) {
        if (--i == 0)
            break;
    }

    if (task == NULL)
        return 0;

    return rand_range((unsigned long)task->thread.sp,
        (unsigned long)task->stack + THREAD_SIZE);
}

static unsigned long get_random_heap_addr(void) 
{
    return 0;
}

static unsigned long get_random_data_addr(void) 
{
    return rand_range((unsigned long)_sdata, (unsigned long)_edata);
}

static unsigned long get_random_bss_addr(void) 
{
    return rand_range((unsigned long)__bss_start, (unsigned long)__bss_stop);
}

/*
 * Binary-level fault injection can be divided into roughly two steps.
 * The first step is to select instructions that are mutated.
 * The second step is to mutate the selected instructions.
 * 
 * Fucntions (test_)do_*(unsigned long addr, size_t byte) are used for the first step.
 * Functions is_*(unsgigned long addr) are used for the second step.
 * You can find how to use their functions in function do_swifi.
 *
 */



/* functions for THE SECOND STEP: mutating an instruction */

static void write_addr(u128 * target, u128 * inject)
{
    pte_t * ppt, pt;
    unsigned int level;

    if(pte_write(*lookup_address((unsigned long)target, &level)) == 0) {
        ppt = lookup_address((unsigned long)target, &level);
        pt = pte_mkwrite(*ppt);
        set_pte(ppt, pt);
        *target = *inject;
        ppt = lookup_address((unsigned long)target, &level);
        pt = pte_wrprotect(*ppt);
        set_pte(ppt, pt);
    }else {
        *target = *inject;
    }
}

static u128 do_nothing(unsigned long addr, size_t byte)
{
    return *(u128 *)addr; 
}

static u128 test_do_bitflip(unsigned long addr, size_t byte) 
{
    u128 target = *(u128 *)addr;
    u64 flip_bit;
    u64 * flip_target;

    flip_bit = (u64)(rand() % (byte * 8));
    if (flip_bit < sizeof(u64) * 8)
        flip_target = &target.low;
    else
        flip_target = &target.high;
    flip_bit = 1L << (flip_bit % (sizeof(u64) * 8));
    *flip_target = *flip_target ^ flip_bit;
    return target;
}

static u128 do_bitflip(unsigned long addr, size_t byte) 
{
    u128 inject = test_do_bitflip(addr, byte);
    write_addr((u128 *)addr, &inject);
    return *(u128 *)addr;
}

static u128 test_do_nop(unsigned long addr, size_t byte) 
{
    u128 target = *(u128 *)addr;
    u8 *p;
    if (byte > sizeof(u128))
        byte = sizeof(u128);
    for (p = (u8 *)&target; p - (u8 *)&target < byte; p++)
        *p = NOP;
    return target;
}

static u128 do_nop(unsigned long addr, size_t byte) 
{
    u128 inject = test_do_nop(addr, byte);
    write_addr((u128 *)addr, &inject);
    return *(u128 *)addr;
}

/* 
 * original dst/src: flip bits in mod/rm, sib, disp or imm fields
 *
 * new dst/src fault checks if the instruction mutation does not corruptt later intructions.
 *
 */

static int inst_not_currupted(unsigned long addr, unsigned long target)
{
    u8 * op1, * op2;
    u8 * mod1, * mod2;
    size_t byte, byte2;

    byte  = do_disasm(addr, NULL);
    op1   = get_opcode_addr();
    mod1  = get_modrm_addr();

    byte2 = do_disasm(target, NULL);
    op2   = get_opcode_addr();
    mod2  = get_modrm_addr();

    if (*op1 != *op2 || byte != byte2)
        return 0;
    /* avoid changing the opcode type by mutating the modrm extension (c.f. AMD manual pp. 349)*/
    if ((0x80 <= *op1 && *op1 <= 0x83) ||
        (*op1 == 0x8f) ||
        (0xc0 <= *op1 && *op1 <= 0xc1) ||
        (0xc6 <= *op1 && *op1 <= 0xc7) ||
        (0xd0 <= *op1 && *op1 <= 0xd3) ||
        (0xf6 <= *op1 && *op1 <= 0xf7) ||
        (0xfe <= *op1 && *op1 <= 0xff)) {
            if (8 <= (*mod1 ^ *mod2) && (*mod1 ^ *mod2) <= 32) //avoid changing reg
                return 0;
    }
    return 1;
}

static u128 test_do_dstsrc(unsigned long addr, size_t byte) 
{
    u128 target = *(u128 *)addr;
    u128 tmp = target; 
    unsigned long start;
    int i;

    for(i = 0; i < 100; i++) {
        do_disasm((unsigned long)&target, NULL);
        start = (unsigned long)get_opcode_addr();
        if (!start || byte <= 1)
            return target;
        if (byte - (start + 1 - (unsigned long)&target) == 0)
            return target;
        do_bitflip(start + 1, byte - (start + 1 - (unsigned long)&target));
        if (inst_not_currupted(addr, (unsigned long)&target))
            break;
        target = tmp;
    }
    return target;
}

static u128 do_dstsrc(unsigned long addr, size_t byte) 
{
    u128 inject = test_do_dstsrc(addr, byte);
    write_addr((u128 *)addr, &inject);
    return *(u128 *)addr;
}

/* 
 * original ptr: if instruction has regmodrm byte,
 * and mod field has address ([eyy]dispxx),
 * eyy!=ebp flip 1 bit in lower byte (0x0f) or any bit in following bytes (sib, imm or disp).
 *
 * new ptr fault excludes nop that has regmodrm.
 *
 */

static u128 test_do_ptr(unsigned long addr, size_t byte) 
{
    u128 target = *(u128 *)addr;
    u128 tmp = target;
    u8 * mod1, * mod2;
    int i;
    for (i = 0; i < 100; i++) {
        target = do_dstsrc((unsigned long)&target, byte);
        do_disasm((unsigned long)&target, NULL);
        mod1 = get_modrm_addr();
        do_disasm((unsigned long)&tmp, NULL);
        mod2 = get_modrm_addr();
        if (0x00 < (*mod1 ^ *mod2) && (*mod1 ^ *mod2) <= 0x0f)
            break;
        if ((target.low ^ tmp.low) || (target.high ^ tmp.high))
            break;
        target = tmp;
    }
    return target;
}

static u128 do_ptr(unsigned long addr, size_t byte) 
{
    u128 inject = test_do_ptr(addr, byte);
    write_addr((u128 *)addr, &inject);
    return *(u128 *)addr;
}

/*
 * inverse fault: inverse a jcc.
 *
 */

static u128 test_do_inverse(unsigned long addr, size_t byte) 
{
    u128 target = *(u128 *)addr;
    u8 * opcode;
    do_disasm((unsigned long)&target, NULL);
    opcode = get_opcode_addr();
    if (!opcode || opcode < (u8 *)&target || opcode >= (u8 *)&target + byte)
        return target;
    if (*opcode == 0x0f)
        opcode++;
    if (*opcode % 2 == 0)
        *opcode += 1;
    else
        *opcode -= 1;
    return target;
}

static u128 do_inverse(unsigned long addr, size_t byte) 
{
    u128 inject = test_do_inverse(addr, byte);
    write_addr((u128 *)addr, &inject);
    return *(u128 *)addr;
}

/* 
 * off by one: search jb,ja,jl,jg,jbe,jae,jle,jge.
 * Then, replace ja with jae, jae with ja, etc.
 *
 */

static u128 test_do_offbyone(unsigned long addr, size_t byte)
{
    u128 target = *(u128 *)addr;
    u8 * opcode;
    do_disasm((unsigned long)&target, NULL);
    opcode = get_opcode_addr();
    if (!opcode || opcode < (u8 *)&target || opcode >= (u8 *)&target + byte)
        return target;

    if (*opcode == 0x72) //jb
        *opcode = 0x76;
    else if (*opcode == 0x73) //jae
        *opcode = 0x77;
    else if (*opcode == 0x76) //jbe
        *opcode = 0x72;
    else if (*opcode == 0x77) //ja
        *opcode = 0x73;
    else if (*opcode == 0x7c) //jl
        *opcode = 0x7e;
    else if (*opcode == 0x7d) //jge
        *opcode = 0x7f;
    else if (*opcode == 0x7e) //jle
        *opcode = 0x7c;
    else if (*opcode == 0x7f) //jg
        *opcode = 0x7d;

    if (*opcode == 0x0f)
        opcode++;

    if (*opcode == 0x82) //jb
        *opcode = 0x86;
    else if (*opcode == 0x83) //jae
        *opcode = 0x87;
    else if (*opcode == 0x86) //jbe
        *opcode = 0x82;
    else if (*opcode == 0x87) //ja
        *opcode = 0x83;
    else if (*opcode == 0x8c) //jl
        *opcode = 0x8e;
    else if (*opcode == 0x8d) //jge
        *opcode = 0x8f;
    else if (*opcode == 0x8e) //jle
        *opcode = 0x8c;
    else if (*opcode == 0x8f) //jg
        *opcode = 0x8d;

    return target;
}

static u128 do_offbyone(unsigned long addr, size_t byte) 
{
    u128 inject = test_do_offbyone(addr, byte);
    write_addr((u128 *)addr, &inject);
    return *(u128 *)addr;
}

/*
 * Most functions return values with the AX register.
 * Therefore, replacing a call instruction into xor AX,AX emulates 
 * the case where a function returns zero.
 *
 */

static u128 test_do_retzero(unsigned long addr, size_t byte) 
{
    u128 target = *(u128 *)addr;
    u128 xorraxrax;
    u8 * p;

    memset(&xorraxrax, NOP, sizeof(u128));
    p = (u8 *)&xorraxrax;

#if defined(CONFIG_X86_64)
    *p++ = 0x48;
    *p++ = 0x31;
    *p++ = 0xc0;    //0x4831c0 == xor %rax, %rax (set zero to return value)
    if (byte < 3)
        return target;
#elif defined(CONFIG_X86_32)
    *p++ = 0x31;
    *p++ = 0xc0;    //0x31c0 == xor %eax, %eax (set zero to return value)
    if (byte < 2)
        return target;
#endif

    memcpy(&target, &xorraxrax, byte); //write a call instruction with the xor
    return target;
}

static u128 do_retzero(unsigned long addr, size_t byte) 
{
    u128 inject = test_do_retzero(addr, byte);
    write_addr((u128 *)addr, &inject);
    return *(u128 *)addr;
}

/*
 * size: change the size of kmalloc allocation.
 *
 */

static u128 test_do_size(unsigned long addr, size_t byte)
{
    u128 target = *(u128 *)addr;
    u8 * rex, * opcode, * modrm;
    int i;

    for (i = 0; i < 100; i++) {
        target = test_do_dstsrc(addr, byte);
        do_disasm((unsigned long)&target, NULL);
        rex = get_rex_addr();
        opcode = get_opcode_addr();
        modrm = get_modrm_addr();

        if ((!rex || (rex && (*rex % 2 == 0))) &&
            opcode && *opcode == 0xbf)  //mov imm, %Xdi
            break;
        else if ((!rex || (rex && (*rex % 2 == 0))) &&
            opcode && *opcode == 0xc7 &&
            modrm && *modrm == 0xc7) //mov imm, %Xdi
            break;
        else if ((!rex || (rex && *rex % 2 == 0)) &&
            opcode && *opcode == 0x89 && 
            modrm && (*modrm & 0xc7) == 0xc7) //mov XX, %Xdi
            break;
        else if ((!rex || (rex && (*rex & 0x04) != 0x04)) &&
            opcode && *opcode == 0x8b &&
            modrm && (*modrm & 0x38) == 0x38) //mov XX, %Xdi
            break;
    }

    return target;
}

static u128 do_size(unsigned long addr, size_t byte) 
{
    u128 inject = test_do_size(addr, byte);
    write_addr((u128 *)addr, &inject);
    return *(u128 *)addr;
}

/*
 * bcopy: change bytes manipulated by string functions like strcpy.
 * This fault mutates a mov imm,CX before a rep.
 *
 */

static u128 test_do_bcopy(unsigned long addr, size_t byte)
{
    u128 target = *(u128 *)addr;
    u8 * rex, * opcode, * modrm;
    int i;

    for (i = 0; i < 100; i++) {
        target = test_do_dstsrc(addr, byte);
        do_disasm((unsigned long)&target, NULL);
        rex = get_rex_addr();
        opcode = get_opcode_addr();
        modrm = get_modrm_addr();
        if ((!rex || (rex && (*rex % 2 == 0))) &&
            opcode && *opcode == 0xb9)  //mov imm, %Xcx
            break;
        else if ((!rex || (rex && (*rex % 2 == 0))) &&
            opcode && *opcode == 0xc7 &&
            modrm && *modrm == 0xc1) //mov imm, %Xcx
            break;
        else if ((!rex || (rex && *rex % 2 == 0)) &&
            opcode && *opcode == 0x89 && 
            modrm && (*modrm & 0xc7) == 0xc1) //mov XX, %Xcx
            break;
        else if ((!rex || (rex && (*rex & 0x04) != 0x04)) &&
            opcode && *opcode == 0x8b &&
            modrm && (*modrm & 0x38) == 0x08) //mov XX, %Xcx
            break;
    }

    return target;
}

static u128 do_bcopy(unsigned long addr, size_t byte) 
{
    u128 inject = test_do_bcopy(addr, byte);
    write_addr((u128 *)addr, &inject);
    return *(u128 *)addr;
}



/* functions for mutating two instructions. */

static u128 test_do_mulimm(unsigned long addr, size_t byte)
{
    u128 target = *(u128 *)addr;
    u32 * imm;
    int i;
    do_disasm((unsigned long)&target, NULL);
    imm = (u32 *)(get_modrm_addr()  + 1);
    for (i = 8; i >= 1; i--) {
        if ((*imm << i) < (THREAD_SIZE / 8 * 7)) {
            *imm <<= i;
            break;
        }
    }
    return target;
}

static u128 do_mulimm(unsigned long addr, size_t byte)
{
    u128 inject = test_do_mulimm(addr, byte);
    write_addr((u128 *)addr, &inject);
    return *(u128 *)addr;
}

static u128 test_do_compraxrax(unsigned long addr, size_t byte)
{
    u128 target = *(u128 *)addr;
    u8 * opcode;
    do_disasm((unsigned long)&target, NULL);
    opcode = get_opcode_addr();
    *opcode = 0x39;
    return target;
}

static u128 do_compraxrax(unsigned long addr, size_t byte)
{
    u128 inject = test_do_compraxrax(addr, byte);
    write_addr((u128 *)addr, &inject);
    return *(u128 *)addr;
}



/* functions for THE FIRST STEP: selecting the address of the mutated instruction */

static unsigned long foreach_instr(int (*func)(unsigned long)) {
    unsigned long target;
    unsigned long next;
    int i = 0;

    target = get_random_text_addr();

    while(1) {
        next = do_disasm(target, NULL);
        if (next + target >= tend)
            return 0;
        if (i++ > 10000)
            return 0;
        if(func(target))
            break;
        target += next;
        if (target < tstart || target > tend)
            return 0;
    }
    return target;
}


static unsigned long get_null(void)
{
    return 0;
}

/* 
 * origianl init fault: from SOF, look for movl $X, -Y(%ebp),
 * (C645Fxxx or C745Fxxx) and replace with nop.
 *
 * new init fault doesn't look for them from SOF, but does from a random instruction.
 *
 */

static int is_init(unsigned long addr)
{
    u8 * rex;
    u8 * opcode;
    u8 * modrm;
    u8 dispsize;

    do_disasm(addr, NULL);
    rex    = get_rex_addr();
    opcode = get_opcode_addr();
    modrm  = get_modrm_addr();
    dispsize = get_disp_size();

    if (!opcode || !modrm)
        return 0;

    if (((rex && (*rex | 0x06 == 0x46)) || !rex) &&
        (*opcode == 0xc6 || *opcode == 0xc7) &&
        (*modrm == 0x45 || *modrm == 0x85)) {
            if (dispsize == 8) {
                s8 * disp = (s8 *)get_disp_addr();
                if (*disp < 0)
                    return 1;
                return 0;
            } else if (dispsize == 32) {
                s32 * disp = (s32 *)get_disp_addr();
                if (*disp < 0)
                    return 1;
                return 0;
            }
    }
    return 0;
}

static unsigned long get_init(void)
{
    return foreach_instr(is_init);
}

/* 
 * original ptr: if instruction has regmodrm byte (i_has_modrm),
 * and mod field has address ([eyy]dispxx),
 * eyy!=ebp flip 1 bit in lower byte (0x0f) or any bit in following bytes (sib, imm or disp).
 *
 * new ptr fault excludes nop that has regmodrm
 */

static int is_ptr(unsigned long addr)
{
    int ret = 0;
    char * str = kzalloc(256, GFP_KERNEL);
    if (!str)
        return 0;
    do_disasm(addr, str);
    if (strstr(str, "rbp") || strstr(str, "ebp") || strstr(str, "nop"))  //Too simple... should be rewritten
        ret = 0;
    else if (get_sib_addr() || get_disp_addr())
        ret = 1;
    kfree(str);
    return ret;
}

static unsigned long get_ptr(void)
{
    return foreach_instr(is_ptr);
}

/* 
 * original interface: look for movl XX(ebp), reg or movb XX(ebp), reg, where XX is positive.
 * replace instr with nop. movl=0x8a, movb=0x8b, mod=01XXX101 (disp8[ebp]), disp>0
 *
 * In new version, instructions with mod=10XXX101 is also selected.
 * Apparently, candidate instructions for interface fault are rare in 32 bit mode.
 * This implementation should probably be revised in the future.
 *
 */

static int is_interface(unsigned long addr)
{
    u8 * rex;
    u8 * opcode;
    u8 * modrm;
    u8 dispsize;

    do_disasm(addr, NULL);
    rex    = get_rex_addr();
    opcode = get_opcode_addr();
    modrm  = get_modrm_addr();
    dispsize = get_disp_size();

    if (!opcode || !modrm)
        return 0;

    if ((!rex || ((*rex | 0x06) == 0x46)) &&
        (*opcode == 0x8a || *opcode == 0x8b) &&
        ((*modrm & ~0x38) == 0x85 || (*modrm & ~0x38) == 0x45)) {
            if (dispsize == 8) {
                s8 * disp = (s8 *)get_disp_addr();
                if (disp && *disp > 0)
                    return 1;
                return 0;
            } else if (dispsize == 32) {
                s32 * disp = (s32 *)get_disp_addr();
                if (disp && *disp > 0)
                    return 1;
                return 0;
            }
    }
    return 0;
}

static unsigned long get_interface(void)
{
    return foreach_instr(is_interface);
}

/* original dst/src: flip bits in mod/rm, sib, disp or imm fields */

static int is_dstsrc(unsigned long addr)
{
    u8 * opcode;
    u8 * modrm;

    do_disasm(addr, NULL);
    opcode = get_opcode_addr();
    modrm  = get_modrm_addr();

    if (!opcode || !modrm || *opcode == 0x0f) // do not handle two bytes instruction 
        return 0;
    return 1;
}

static unsigned long get_dstsrc(void)
{
    return foreach_instr(is_dstsrc);
}

/* 
 * original branch: search forward utnil we hit a Jxx or rep (F3 or F2).
 * replace instr with nop.
 *
 * New branch fault ignores rep. This function is also used by inverse falut.
 *
 */

static int is_branch(unsigned long addr)
{
    u8 * opcode;

    do_disasm(addr, NULL);
    opcode = get_opcode_addr();

    if (!opcode)
        return 0;
    else if ((0x70 <= *opcode && *opcode <= 0x7f) ||
        (*opcode == 0x0f && 0x80 <= *(opcode + 1) && *(opcode + 1) <= 0x8F))
        return 1;
    return 0;
}

static unsigned long get_branch(void)
{
    return foreach_instr(is_branch);
}

/* 
 * off by one: search jb,ja,jl,jg,jbe,jae,jle,jge and replace ja with jae, jae with ja, etc.
 *
 */

static int is_offbyone(unsigned long addr)
{
    u8 * opcode, * opcode2;

    do_disasm(addr, NULL);
    opcode = get_opcode_addr();
    opcode2 = opcode + 1;


    if (!opcode)
        return 0;
    if (*opcode == 0x72 || //jb
        *opcode == 0x73 || //jae
        *opcode == 0x76 || //jbe
        *opcode == 0x77 || //ja
        *opcode == 0x7c || //jl
        *opcode == 0x7d || //jge
        *opcode == 0x7e || //jle
        *opcode == 0x7f)   //jg
        return 1;
    if (*opcode == 0x0f &&
        (*opcode2 == 0x82 || //jb
        *opcode2 == 0x83 || //jae
        *opcode2 == 0x86 || //jbe
        *opcode2 == 0x87 || //ja
        *opcode2 == 0x8c || //jl
        *opcode2 == 0x8d || //jge
        *opcode2 == 0x8e || //jle
        *opcode2 == 0x8f))  //jg
        return 1; 
    return 0;
}

static unsigned long get_offbyone(void)
{
    return foreach_instr(is_offbyone);
}

/* 
 * alloc: search an instr calling kmalloc, kmem_cache_alloc, __kmalloc, etc.
 * Then replace xor %rax,%rax which simulates kmalloc misses and returns NULL.
 *
 * free : search an instr callinf free.
 * Then replace nop and simulate missing free and memory leaks.
 *
 */

static int is_callfunc(unsigned long addr, const char * func_name)
{
    u8 * opcode;
    long next;

    if (!addr)
        return 0;

    next = (long)addr + do_disasm(addr, NULL);
    opcode = get_opcode_addr();

    if (opcode && *opcode == 0xe8) { //call
        s32 offset = *(s32 *)(opcode + 1);
        if ((unsigned long)(next + (long)offset) == kallsyms_lookup_name(func_name))
            return 1;
    }
    return 0;
}

static int is_callkfree(unsigned long addr)
{
    int ret = is_callfunc(addr, "kmem_cache_free");
    if (!ret)
        ret = is_callfunc(addr, "kfree");
    return ret;
}

static unsigned long get_callkfree(void)
{
    return foreach_instr(is_callkfree);
}

static int is_callkmalloc(unsigned long addr)
{
    int ret = is_callfunc(addr, "kmem_cache_alloc");
    if (!ret)
        ret = is_callfunc(addr, "__kmalloc");
    if (!ret)
        ret = is_callfunc(addr, "kzalloc");
    if (!ret)
        ret = is_callfunc(addr, "vmalloc");
    if (!ret)
        ret = is_callfunc(addr, "vzalloc");
    return ret;
}

static unsigned long get_callkmalloc(void)
{
    return foreach_instr(is_callkmalloc);
}

static int is_size(unsigned long addr)
{
    int i, ret = 0;
    u8 * rex, * opcode, * modrm;
    unsigned long next;

    next = addr + do_disasm(addr, NULL);

    rex = get_rex_addr();
    opcode = get_opcode_addr();
    modrm  = get_modrm_addr();

    if ((!rex || (rex && (*rex % 2 == 0))) &&
        opcode && *opcode == 0xbf)  //mov imm, %Xdi
        ret = 1;
    else if ((!rex || (rex && (*rex % 2 == 0))) &&
        opcode && *opcode == 0xc7 &&
        modrm && *modrm == 0xc7) //mov imm, %Xdi
        ret = 1;
    else if ((!rex || (rex && *rex % 2 == 0)) &&
        opcode && *opcode == 0x89 && 
        modrm && (*modrm & 0xc7) == 0xc7) //mov XX, %Xdi
        ret = 1;
    else if ((!rex || (rex && (*rex & 0x04) != 0x04)) &&
        opcode && *opcode == 0x8b &&
        modrm && (*modrm & 0x38) == 0x38) //mov XX, %Xdi
        ret = 1;

    if (!ret)
        return 0;

    for (i = 0; i < 5; i ++) {
        if (is_callfunc(next, "__kmalloc") || is_callfunc(next, "kzalloc"))
            return 1;
        next += do_disasm(next, NULL);
        if (next >= tend)
            return 0;
    }
    return 0;
}

static unsigned long get_size(void)
{
    return foreach_instr(is_size);
}

static int is_bcopy(unsigned long addr)
{
    int i, ret = 0;
    char * str = kzalloc(256, GFP_KERNEL);
    u8 * rex, * opcode, * modrm;
    unsigned long next;

    if (!str)
        return 0;

    next = addr + do_disasm(addr, str);
    rex = get_rex_addr();
    opcode = get_opcode_addr();
    modrm  = get_modrm_addr();

    if ((!rex || (rex && (*rex % 2 == 0))) &&
        opcode && *opcode == 0xb9)  //mov imm, %Xcx
        ret = 1;
    else if ((!rex || (rex && (*rex % 2 == 0))) &&
        opcode && *opcode == 0xc7 &&
        modrm && *modrm == 0xc1) //mov imm, %Xcx
        ret = 1;
    else if ((!rex || (rex && *rex % 2 == 0)) &&
        opcode && *opcode == 0x89 && 
        modrm && (*modrm & 0xc7) == 0xc1) //mov XX, %Xcx
        ret = 1;
    else if ((!rex || (rex && (*rex & 0x04) != 0x04)) &&
        opcode && *opcode == 0x8b &&
        modrm && (*modrm & 0x38) == 0x08) //mov XX, %Xcx
        ret = 1;

    if (!ret)
        goto final;

    ret = 0;

    for (i = 0; i < 5; i ++) {
        if (strstr(str, " rep")) {  // Too simple... should be rewritten
            ret = 1;
            break;
        }
        next += do_disasm(next, str);
        if (next >= tend)
            goto final;
    }
final:
    kfree(str);
    return ret;
}

static unsigned long get_bcopy(void)
{
    return foreach_instr(is_bcopy);
}

static int is_loop(unsigned long addr)
{
    int i, ret = 0;
    char * str = kzalloc(256, GFP_KERNEL);
    u8 * opcode;
    unsigned long next;

    if (!str)
        return 0;

    next = addr + do_disasm(addr, str);
    opcode = get_opcode_addr();

    if (!strstr(str, " cmp"))     //Too simple... should be rewritten
        goto final;

    ret = 0;

    for (i = 0; i < 5; i ++) {
        unsigned long byte = do_disasm(next, NULL);
        if (next >= tend)
            goto final;
        opcode = get_opcode_addr();
        if (is_branch(next)) {
            if (byte == 2 && *(s8 *)(opcode + 1) < 0) {
                ret = 1;
                break;
            } else if (byte == 6 && *(s32 *)(opcode + 2) < 0) {
                ret = 1;
                break;
            }
        }
        next += byte;
    }
final:
    kfree(str);
    return ret;
}

static unsigned long get_loop(void)
{
    return foreach_instr(is_loop);
}

/* 
 * is_irq works in x86_64 linux 2.6.38, but does not work in 3.x apparently.
 * Use NEWIRQ which replaces push & popf with two nops.
 *
 */

static int is_irq(unsigned long addr)
{
    u8 * opcode;
    long next;
    char func_name[256];

    if (!addr)
        return 0;

    next = (long)addr + do_disasm(addr, NULL);
    opcode = get_opcode_addr();

    if (opcode && *opcode == 0xe8) { //call
        s32 offset = *(s32 *)(opcode + 1);
        kallsyms_lookup((unsigned long)(next + (long)offset), NULL, NULL, NULL, func_name);
        if (strcmp(func_name, "arch_local_irq_restore") == 0)
            return 1;
        if (strcmp(func_name, "raw_local_irq_restore") == 0)
            return 1;
    }

    return 0;
}

static unsigned long get_irq(void)
{
    return foreach_instr(is_irq);
}

/* functions for mutating two instructions */

static u32 imm_addrsp(unsigned long addr)
{
    u8 *p = (u8 *)addr;
    size_t byte = do_disasm(addr, NULL);
    if (byte == 7 && *p++ == 0x48 && *p++ == 0x81 && *p++ == 0xc4)
        return *(u32 *)p;
    if (byte ==6 && *p++ == 0x81 && *p++ == 0xc4)
        return *(u32 *)p;
    return -1;
}

static u32 imm_subrsp(unsigned long addr)
{
    u8 * p = (u8 *)addr;
    size_t byte = do_disasm(addr, NULL);
    if (byte == 7 && *p++ == 0x48 && *p++ == 0x81 && *p++ == 0xec)
        return *(u32 *)p;
    if (byte == 6 && *p++ == 0x81 && *p++ == 0xec)
        return *(u32 *)p;
    return -1;
}

static addrs get_var(void)
{
    unsigned long target;
    unsigned long next;
    unsigned long end, offset;
    addrs addrs_zero = {.addr1=0, .addr2=0};
    addrs ret;
    char * namebuf;
    int i = 0;
    u32 sub = 0, add = 0;

    namebuf = kzalloc(256, GFP_KERNEL);
retry:
    ret = addrs_zero;
    sub = add = 0;
    target = get_random_text_addr();
    kallsyms_lookup(target, &end, &offset, NULL, namebuf);
    target -= offset;
    end += target;
    memset(namebuf, 0, 256);

    while (target < end){
        next = do_disasm(target, namebuf);
        if (target >= tend)
            return addrs_zero;
        if(!sub && !add && (sub = imm_subrsp(target) != -1)) {
            ret.addr1 = target;
        } else if(sub && !add && (add = imm_addrsp(target) != -1)) {
            ret.addr2 = target;
        } else if (add && imm_addrsp(target) != -1){   //add IMM, %rsp appear twice
            goto retry;
        }
        target += next;
    }
    if (add != -1 && add != 0 && sub != -1 && sub != 0 && add == sub) {
        kfree(namebuf);
        return ret;
    }
    if (i++ < 100)
        goto retry;
    kfree(namebuf);
    return addrs_zero;
}

static int is_testraxrax(unsigned long addr)
{
    u8 * p = (u8 *)addr;
    size_t byte = do_disasm(addr, NULL);
#if defined(CONFIG_X86_64)
    if (byte == 3 && *p++ == 0x48 && *p++ == 0x85 && *p++ == 0xc0)    // xor %rax, %rax
        return 1;
#else
    if (byte == 2 && *p++ == 0x85 && *p++ == 0xc0)                       // xor %eax, %eax
        return 1;
#endif
    return 0;
}

static int is_jejne(unsigned long addr)
{
    u8 * p = (u8 *)addr;
    size_t byte = do_disasm(addr, NULL);
    if ((byte == 2 && *p == 0x74) || (byte == 6 && *p == 0x0f && *p == 0x84))
        return 1;
    else if ((byte == 2 && *p == 0x75) || (byte == 6 && *p == 0x0f && *p == 0x85))
        return 1;
    return 0;
}

static addrs get_null2(void)
{
    addrs zero = {.addr1=0, .addr2 = 0};
    return zero;
}

static addrs get_nullcheck(void)
{
    unsigned long target;
    unsigned long test = 0;
    unsigned long next;
    addrs addrs_zero = {.addr1=0, .addr2=0};
    addrs ret = addrs_zero;
    int i = 0;

    target = get_random_text_addr();

    while (1){
        next = do_disasm(target, NULL);
        if (target >= tend)
            return addrs_zero;
        if (i++ > 10000)
            return addrs_zero;
        if(!test && is_testraxrax(target)){
            test = target;
            continue;
        }
        if(test && is_jejne(target)) {
            ret.addr1 = test;
            ret.addr2 = target;
            return ret;
        } else if (is_branch(target)) {
            return addrs_zero;
        }
        target += next;
    }
    return addrs_zero;
}

static int is_push(unsigned long addr)
{
    u8 * p = (u8 *)addr;
    size_t byte = do_disasm(addr, NULL);
    if (byte == 1 && ((0x50 <= *p ) && (*p <= 0x57))) //push reg
        return 1;
    return 0;
}

static int is_popf(unsigned long addr)
{
    u8 * p = (u8 *)addr;
    size_t byte = do_disasm(addr, NULL);
    if (byte == 1 && *p == 0x9d)            //popf
        return 1;
    return 0;
}

/* 
 * look for push reg or offset(reg) / popf, where XX is positive. replace instr with nop. 
 * push & popf is inlined local_irq_restore.
 */

static addrs get_irq_restore(void)
{
    unsigned long target;
    unsigned long test = 0;
    unsigned long next;
    addrs addrs_zero = {.addr1=0, .addr2=0};
    addrs ret = addrs_zero;
    int i = 0;

    target = get_random_text_addr();

    while (1){
        next = do_disasm(target, NULL);
        if (target >= tend)
            return addrs_zero;
        if (i++ > 10000)
            return addrs_zero;
        if(is_push(target)){
            test = target;
            target += next;
            do_disasm(target, NULL);
            if (!is_popf(target))
                continue;
            ret.addr1 = test;
            ret.addr2 = target;
            return ret;
        }
        target += next;
    }
    return addrs_zero;
}

/* 
 * functions for reporting fault injection results
 *
 * result_stack: used when injected faults to kernel stacks 
 * result_text: used when injected faults to the kernel text
 * result_other: used when injected faults to other kerenel segments
 * result_nothing: used when cmd is unkonwn
 *
 */

static void result_stack(struct swifi_result * res)
{
    snprintf(res->str, 99, "pid:%d(%s)",
        ((struct thread_info *)(res->target & (0L - THREAD_SIZE)))->task->pid,
        ((struct thread_info *)(res->target & (0L - THREAD_SIZE)))->task->comm);
}

static void result_other(struct swifi_result * res)
{
    snprintf(res->str, 99, "address:%lx", res->target);
}

static void result_text(struct swifi_result * res)
{
    unsigned long offset;
    char * namebuf;

    namebuf = kzalloc(256, GFP_KERNEL);
    if (!namebuf)
        return;
    kallsyms_lookup(res->target, NULL, &offset, NULL, namebuf);
    snprintf(res->str, 99, "symbol:%s+0x%lx", namebuf, offset);
    do_disasm((bfd_vma)&res->old_content, res->old_instr);
    do_disasm((bfd_vma)&res->new_content, res->new_instr);
    kfree(namebuf);
}

static void result_nothing(struct swifi_result * res)
{
    snprintf(res->str, 99, "nothing to do");
}


static void result_text2(struct swifi_result2 * res)
{
    unsigned long offset;
    char * namebuf;

    namebuf = kzalloc(256, GFP_KERNEL);
    if (!namebuf)
        return;
    kallsyms_lookup(res->target.addr1, NULL, &offset, NULL, namebuf);
    snprintf(res->str, 100, "symbol:%s+0x%lx", namebuf, offset);
    do_disasm((bfd_vma)&res->old_content, res->old_instr);
    do_disasm((bfd_vma)&res->new_content, res->new_instr);

    memset(namebuf, 0, 256);

    kallsyms_lookup(res->target.addr2, NULL, &offset, NULL, namebuf);
    snprintf(res->str2, 100, "symbol:%s+0x%lx", namebuf, offset);
    do_disasm((bfd_vma)&res->old_content2, res->old_instr2);
    do_disasm((bfd_vma)&res->new_content2, res->new_instr2);

    kfree(namebuf);
}

static void result_nothing2(struct swifi_result2 * res)
{
    snprintf(res->str, 100, "nothing to do");
    snprintf(res->str2, 100, "nothing to do");
}

static int is_text_fault(int cmd)
{
    switch(cmd) {
    case SWIFI_TEXT:
    case SWIFI_BRANCH:
    case SWIFI_INVERSE:
    case SWIFI_PTR:
    case SWIFI_DSTSRC:
    case SWIFI_INTERFACE:
    case SWIFI_INIT:
    case SWIFI_OFFBYONE:
    case SWIFI_ALLOC:
    case SWIFI_FREE:
    case SWIFI_SIZE:
    case SWIFI_BCOPY:
    case SWIFI_LOOP:
    case SWIFI_IRQ:
    case SWIFI_TEST_TEXT:
    case SWIFI_TEST_BRANCH:
    case SWIFI_TEST_INVERSE:
    case SWIFI_TEST_PTR:
    case SWIFI_TEST_DSTSRC:
    case SWIFI_TEST_INTERFACE:
    case SWIFI_TEST_INIT:
    case SWIFI_TEST_OFFBYONE:
    case SWIFI_TEST_ALLOC:
    case SWIFI_TEST_FREE:
    case SWIFI_TEST_SIZE:
    case SWIFI_TEST_BCOPY:
    case SWIFI_TEST_LOOP:
    case SWIFI_TEST_IRQ:
        return 1;
    }
    return 0;
}

static int is_data_fault(int cmd)
{
    switch(cmd) {
    case SWIFI_STACK:
    case SWIFI_HEAP:
    case SWIFI_DATA:
    case SWIFI_BSS:
    case SWIFI_TEST_STACK:
    case SWIFI_TEST_HEAP:
    case SWIFI_TEST_DATA:
    case SWIFI_TEST_BSS:
        return 1;
    }
    return 0;
}

struct swifi_op {
    int cmd;
    u128 (*inject_fault)(unsigned long, size_t);
    unsigned long (*get_target)(void);
    void (*result_report)(struct swifi_result *);
};

static struct swifi_op sop[] = {
    {SWIFI_TEXT,      do_bitflip, get_random_text_addr,  result_text},
    {SWIFI_STACK,     do_bitflip, get_random_stack_addr, result_stack},
    {SWIFI_HEAP,      do_bitflip, get_random_heap_addr,  result_other},
    {SWIFI_DATA,      do_bitflip, get_random_data_addr,  result_other},
    {SWIFI_BSS,       do_bitflip, get_random_bss_addr,   result_other},
    {SWIFI_BRANCH,    do_nop,     get_branch,            result_text},
    {SWIFI_INVERSE,   do_inverse, get_branch,            result_text},
    {SWIFI_PTR,       do_ptr,     get_ptr,               result_text},
    {SWIFI_DSTSRC,    do_dstsrc,  get_dstsrc,            result_text},
    {SWIFI_INTERFACE, do_nop,     get_interface,         result_text},
    {SWIFI_INIT,      do_nop,     get_init,              result_text},
    {SWIFI_OFFBYONE,  do_offbyone,get_offbyone,          result_text},
    {SWIFI_ALLOC,     do_retzero, get_callkmalloc,       result_text},
    {SWIFI_FREE,      do_nop,     get_callkfree,         result_text},
    {SWIFI_SIZE,      do_size,    get_size,              result_text},
    {SWIFI_BCOPY,     do_bcopy,   get_bcopy,             result_text},
    {SWIFI_LOOP,      do_dstsrc,  get_loop,              result_text},
    {SWIFI_IRQ,       do_nop,     get_irq,               result_text},

    {SWIFI_TEST_TEXT,      test_do_bitflip, get_random_text_addr,  result_text},
    {SWIFI_TEST_STACK,     test_do_bitflip, get_random_stack_addr, result_stack},
    {SWIFI_TEST_HEAP,      test_do_bitflip, get_random_heap_addr,  result_other},
    {SWIFI_TEST_DATA,      test_do_bitflip, get_random_data_addr,  result_other},
    {SWIFI_TEST_BSS,       test_do_bitflip, get_random_bss_addr,   result_other},
    {SWIFI_TEST_BRANCH,    test_do_nop,     get_branch,            result_text},
    {SWIFI_TEST_INVERSE,   test_do_inverse, get_branch,            result_text},
    {SWIFI_TEST_PTR,       test_do_ptr,     get_ptr,               result_text},
    {SWIFI_TEST_DSTSRC,    test_do_dstsrc,  get_dstsrc,            result_text},
    {SWIFI_TEST_INTERFACE, test_do_nop,     get_interface,         result_text},
    {SWIFI_TEST_INIT,      test_do_nop,     get_init,              result_text},
    {SWIFI_TEST_OFFBYONE,  test_do_offbyone,get_offbyone,          result_text},
    {SWIFI_TEST_ALLOC,     test_do_retzero, get_callkmalloc,       result_text},
    {SWIFI_TEST_FREE,      test_do_nop,     get_callkfree,         result_text},
    {SWIFI_TEST_SIZE,      test_do_size,    get_size,              result_text},	
    {SWIFI_TEST_BCOPY,     test_do_bcopy,   get_bcopy,             result_text},
    {SWIFI_TEST_LOOP,      test_do_dstsrc,  get_loop,              result_text},
    {SWIFI_TEST_IRQ,       test_do_nop,     get_irq,               result_text},
    /* add new swifi_op from this line */
    {SWIFI_DONOTHING, do_nothing, get_null, result_nothing}
};

long do_swifi(int cmd, struct swifi_result __user * result)
{
    int ret = -1;
    size_t byte;
    struct swifi_op * op;
    struct swifi_result * res = kzalloc(sizeof(struct swifi_result), GFP_KERNEL);

    if (!res)
        return -1;

    op = &sop[(cmd < SWIFI_DONOTHING)?cmd:SWIFI_DONOTHING];
    res->target = op->get_target();
    if (probe_kernel_read(&res->old_content, (u128 *)res->target, sizeof(u128)))
        goto final;

    if (is_text_fault(op->cmd) && __kernel_text_address(res->target)) {
        byte = do_disasm((unsigned long)&res->old_content, NULL);
        if (byte > sizeof(u128))
            goto final;
    } else if (is_data_fault(op->cmd)){
        byte = sizeof(u128);
    } else
        goto final;

    res->new_content = op->inject_fault(res->target, byte);
    op->result_report(res);
    ret = copy_to_user(result, res, sizeof(struct swifi_result));
final:
    kfree(res);
    return ret;
}

SYSCALL_DEFINE4(swifi, const char __user *, name, int, cmd, unsigned long, seed, struct swifi_result __user *, result)
{
    long ret = 0;
    char str[128];

    srand(seed);

    if (copy_from_user(str, name, 128))
        return -1;

    if (strcmp(str, "core") == 0) {
        tstart = (unsigned long)_stext;
        tend   = (unsigned long)_etext;
        ret = do_swifi(cmd, result);
    } else {
        struct module * mod =  find_module(str);
        if (!mod)
            return -1;
        tstart = (unsigned long)mod->module_core;
        tend   = (unsigned long)mod->module_core + mod->core_text_size;
        ret = do_swifi(cmd, result);
    }
    return ret;
}


struct swifi_op2 {
    int cmd;
    u128 (*inject_fault)(unsigned long, size_t);
    u128 (*inject_fault2)(unsigned long, size_t);
    addrs (*get_target)(void);
    void (*result_report)(struct swifi_result2 *);
};

static struct swifi_op2 sop2[] = {
    {SWIFI_VAR,        do_mulimm,     do_mulimm,    get_var,        result_text2},
    {SWIFI_NULL,       do_compraxrax,   do_inverse,     get_nullcheck,  result_text2},
    {SWIFI_NEWIRQ,     do_nop,          do_nop,     get_irq_restore,    result_text2},
    {SWIFI_TEST_VAR,        test_do_mulimm,     test_do_mulimm,    get_var,        result_text2},
    {SWIFI_TEST_NULL,       test_do_compraxrax,   test_do_inverse,     get_nullcheck,  result_text2},
    {SWIFI_TEST_NEWIRQ,     test_do_nop,          test_do_nop,     get_irq_restore,    result_text2},
    /* add new swifi_op from this line */
    {SWIFI_DONOTHING2, do_nothing, do_nothing,  get_null2,       result_nothing2}
};

long do_swifi2(int cmd, struct swifi_result2 __user * result)
{
    int ret = -1;
    size_t byte, byte2;
    struct swifi_op2 * op;
    struct swifi_result2 * res = kzalloc(sizeof(struct swifi_result2), GFP_KERNEL);

    if (!res)
        return -1;

    op = &sop2[(cmd < SWIFI_DONOTHING2)?cmd:SWIFI_DONOTHING2];
    res->target = op->get_target();
    if (probe_kernel_read(&res->old_content, (u128 *)res->target.addr1, sizeof(u128)) ||
        probe_kernel_read(&res->old_content2, (u128 *)res->target.addr2, sizeof(u128)))
        goto final;

    if (__kernel_text_address(res->target.addr1) &&
        __kernel_text_address(res->target.addr2)) {
            byte = do_disasm((unsigned long)&res->old_content, NULL);
            byte2 = do_disasm((unsigned long)&res->old_content2, NULL);
            if (byte > sizeof(u128) || byte2 > sizeof(u128))
                goto final;
    } else 
        goto final;

    res->new_content = op->inject_fault(res->target.addr1, byte);
    res->new_content2 = op->inject_fault2(res->target.addr2, byte2);
    op->result_report(res);
    ret = copy_to_user(result, res, sizeof(struct swifi_result2));
final:
    kfree(res);
    return ret;
}

SYSCALL_DEFINE4(swifi2, const char __user *, name, int, cmd, unsigned long, seed, struct swifi_result2 __user *, result)
{
    long ret = 0;
    char str[128];

    srand(seed);

    if (copy_from_user(str, name, 128))
        return -1;

    if (strcmp(str, "core") == 0) {
        tstart = (unsigned long)_stext;
        tend   = (unsigned long)_etext;
        ret = do_swifi2(cmd, result);
    } else {
        struct module * mod =  find_module(str);
        if (!mod)
            return -1;
        tstart = (unsigned long)mod->module_core;
        tend   = (unsigned long)mod->module_core + mod->core_text_size;
        ret = do_swifi2(cmd, result);
    }

    return ret;
}
