/*
 *  swifi.c
 *  Created on: Feb 20, 2012
 *      Author: Takeshi Yoshimura
 *  SWIFI is originally created by Ng and Swift
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <asm/pgalloc.h>
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
#if defined(CONFIG_X86_32)
static const long RND_STUFF = 0x7fffffff;
#elif defined(CONFIG_X86_64)
static const long RND_STUFF = 0x7fffffffffffffff;
#endif

static unsigned long tstart = (unsigned long)_stext;
static unsigned long tend = (unsigned long)_etext;

/* functions for getting random & deterministic integers */

static unsigned long seed = 1;

static void srand(unsigned long random_seed) 
{
	seed = random_seed;
}

static unsigned long rand(void) 
{
	long x, hi, lo, t;
	
	x = seed;
	hi = x / 127773;
	lo = x % 127773;
	t = 16807 * lo - 2836 * hi;
	if (t <= 0)
		t += RND_STUFF;
	seed = t;
	return t;
}

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
	
	while(tstart > target || target > tend) {
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



/* functions to change instructions as a fault */

static void force_to_write(u128 * target, u128 * inject)
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
	force_to_write((u128 *)addr, &inject);
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
	//printk(KERN_INFO "&target=%p, byte=%u\n", &target, byte);
    return target;
}

static u128 do_nop(unsigned long addr, size_t byte) 
{
    u128 inject = test_do_nop(addr, byte);
	force_to_write((u128 *)addr, &inject);
    return *(u128 *)addr;
}

/* original dst/src: flip bits in mod/rm, sib, disp or imm fields
 *
 * new dst/src fault checks if sizeof instruction remains 
 * not to corrupt later intructions.
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
    /* avoid opcode change by changing modrm extension (c.f. AMD manual pp. 349)*/
    if ((0x80 <= *op1 && *op1 <= 0x83) ||
        (*op1 == 0x8f) ||
        (0xc0 <= *op1 && *op1 <= 0xc1) ||
        (0xc6 <= *op1 && *op1 <= 0xc7) ||
        (0xd0 <= *op1 && *op1 <= 0xd3) ||
        (0xf6 <= *op1 && *op1 <= 0xf7) ||
        (0xfe <= *op1 && *op1 <= 0xff)) {
        if (8 <= (*mod1 ^ *mod2) && (*mod1 ^ *mod2) <= 32) //avoid to change reg
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
	force_to_write((u128 *)addr, &inject);
    return *(u128 *)addr;
}

/* original ptr: if instruction has regmodrm byte,
 * and mod field has address ([eyy]dispxx),
 * eyy!=ebp flip 1 bit in lower byte (0x0f) or any bit in following bytes (sib, imm or disp).
 *
 * new ptr fault excludes nop with regmodrm
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
	force_to_write((u128 *)addr, &inject);
    return *(u128 *)addr;
}

/* original inverse fault is loop fault,but original loop fault does almost only inverse jmp instructions.
 * loop fault handles rep instruction, but new inverse fault doesn't handle.
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
	force_to_write((u128 *)addr, &inject);
    return *(u128 *)addr;
}

/* off by one: search forward until we hit jb,ja,jl,jg,jbe,jae,jle,jge
 * replace ja with jae, jae with ja, etc.
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
	force_to_write((u128 *)addr, &inject);
    return *(u128 *)addr;
}

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

    memcpy(&target, &xorraxrax, byte); //overwrite call with xor
    return target;
}

static u128 do_retzero(unsigned long addr, size_t byte) 
{
    u128 inject = test_do_retzero(addr, byte);
	force_to_write((u128 *)addr, &inject);
    return *(u128 *)addr;
}

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
	force_to_write((u128 *)addr, &inject);
    return *(u128 *)addr;
}

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
	force_to_write((u128 *)addr, &inject);
    return *(u128 *)addr;
}

/* functions to target address to inject a fault
 */

static unsigned long foreach_instr(int (*func)(unsigned long)) {
    unsigned long target;
	unsigned long next;
	int i = 0;

	target = get_random_text_addr();

	while(1) {
		next = do_disasm(target, NULL);
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

/* origianl init fault: from SOF, look for movl $X, -Y(%ebp),
 * (C645Fxxx or C745Fxxx) and replace with nop.
 *
 * new init fault doesn't look for them from SOF but from a random instruction.
 * REX == 40 or 42 or 44 or 46, opcode == C6 or C7, modRM == 45 or 85, and disp < 0
 * if not found over 1000 instructions, then return NULL
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

/* original ptr: if instruction has regmodrm byte (i_has_modrm),
 * and mod field has address ([eyy]dispxx),
 * eyy!=ebp flip 1 bit in lower byte (0x0f) or any bit in following bytes (sib, imm or disp).
 *
 * new ptr fault excludes nop with regmodrm
 */

static int is_ptr(unsigned long addr)
{
	int ret = 0;
	char * str = kzalloc(256, GFP_KERNEL);
	if (!str)
		return 0;
	do_disasm(addr, str);
	if (strstr(str, "rbp") || strstr(str, "ebp") || strstr(str, "nop"))
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

/* original interface: look for movl XX(ebp), reg or movb XX(ebp), reg, where XX is positive.
 * replace instr with nop. movl=0x8a, movb=0x8b, mod=01XXX101 (disp8[ebp]), disp>0
 *
 * in new version, mod=10XXX101 is also targeted
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

	if (!opcode || !modrm || *opcode == 0x0f) // don't handle two bytes instruction 
		return 0;
	return 1;
}

static unsigned long get_dstsrc(void)
{
	return foreach_instr(is_dstsrc);
}

/* original branch: search forward utnil we hit a Jxx or rep (F3 or F2).
 * replace instr with nop.
 * this function is also used for inverse falut.
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

/* off by one: search forward until we hit jb,ja,jl,jg,jbe,jae,jle,jge
 * replace ja with jae, jae with ja, etc.
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

/* alloc: search an instr to calling kmalloc(actually kmem_cache_alloc, __kmalloc, etc.)
 * then replace xor %rax,%rax which simulates kmalloc misses and returns NULL
 * free : search an instr to call free
 * then replace nop and simulate missing free and leaking memory 
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
		if (strstr(str, "rep")) {
			ret = 1;
			break;
		}
		next += do_disasm(next, str);
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

	if (!strstr(str, "cmp"))
		goto final;

	ret = 0;

	for (i = 0; i < 5; i ++) {
		unsigned long byte = do_disasm(next, NULL);
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
        if (strcmp(func_name, "native_restore_fl") == 0)
            return 1;
    }
	return 0;
}

static unsigned long get_irq(void)
{
	return foreach_instr(is_irq);
}

/* 4 functions for reporting fault injection results
 *
 * result_stack: used when injected faults to kernel stacks 
 * result_text: used when injected faults to kernel text
 * result_other: used when injected faults to other kerenel segments
 * result_nothing: used when cmd is unkonwn
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
    printk(KERN_INFO "------------------sys_swifi-------------------\n");
    printk(KERN_INFO "cmd=%2d seed=%lu\n", cmd, seed);
    printk(KERN_INFO "addr: %lx (%s)\n", 
	(unsigned long)result->target, result->str);
    printk(KERN_INFO "change %016lx %016lx to %016lx %016lx\n",
	(unsigned long)result->old_content.low, 
	(unsigned long)result->old_content.high,
	(unsigned long)result->new_content.low, 
	(unsigned long)result->new_content.high);
    printk(KERN_INFO "old instruction: %s\n", result->old_instr);
    printk(KERN_INFO "new instruction: %s\n", result->new_instr);
    printk(KERN_INFO "------------------sys_swifi-------------------\n");
    return ret;
}

SYSCALL_DEFINE1(direct_swifi, struct swifi_result __user *, s)
{
    int ret = -1;
	struct swifi_result * res = kzalloc(sizeof(struct swifi_result), GFP_KERNEL);
    
    if (!res)
        return -1;
    if (copy_from_user(res, s, sizeof(struct swifi_result))) 
        goto final;
    if (probe_kernel_read(&res->old_content, (u128 *)res->target, sizeof(u128 *))) 
        goto final;
    force_to_write((u128 *)res->target, &res->new_content);
    ret = copy_to_user(s, res, sizeof(struct swifi_result));
final:
    kfree(res);
    return ret;
}

