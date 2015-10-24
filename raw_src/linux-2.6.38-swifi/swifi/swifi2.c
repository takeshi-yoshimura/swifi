/*
 *  swifi.c
 *  Created on: Feb 20, 2012
 *      Author: Takeshi Yoshimura
 *  SWIFI is originally created by Ng and Swift
 */

#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <asm/pgalloc.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm/sections.h>
#include <linux/slab.h>
#include <asm/types.h>
#include "dis-asm.h"
#include "swifi2.h"

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

static void show_u128(u128 * str) 
{
    char str2[256];
    u8 * p;
    memset(str2, 0, 256);
    p = (u8 *)str;
    snprintf(str2, 256, "%x", *p);
    for (p = (u8 *)str + 1; p < (u8 *)str + sizeof(u128); p++)
        snprintf(str2, 256, "%s %x", str2, *p);
    printk(KERN_INFO "0x%p: %s\n", str, str2);
}

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
	if (byte > sizeof(u128))
        byte = sizeof(u128);
	memset(&target, NOP, byte);
    return target;
}

static u128 do_nop(unsigned long addr, size_t byte) 
{
    u128 inject = test_do_nop(addr, byte);
	force_to_write((u128 *)addr, &inject);
    return *(u128 *)addr;
}

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
	force_to_write((u128 *)addr, &inject);
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
	force_to_write((u128 *)addr, &inject);
    return *(u128 *)addr;
}

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

static u32 imm_addrsp(unsigned long addr)
{
	u8 *p = (u8 *)addr;
	size_t byte = do_disasm(addr, NULL);
	if (byte == 7 && *p++ == 0x48 && *p++ == 0x81 && *p++ == 0xc4)
		return *(u32 *)p;
	return -1;
}

static u32 imm_subrsp(unsigned long addr)
{
	u8 * p = (u8 *)addr;
	size_t byte = do_disasm(addr, NULL);
	if (byte == 7 && *p++ == 0x48 && *p++ == 0x81 && *p++ == 0xec)
		return *(u32 *)p;
	return -1;
}

static u128 get_var(void)
{
    unsigned long target;
	unsigned long next;
	unsigned long end, offset;
	u128 u128_zero = {.low=0, .high=0};
	u128 ret;
	char * namebuf;
	int i = 0;
	u32 sub = 0, add = 0;

	namebuf = kzalloc(256, GFP_KERNEL);
retry:
	ret = u128_zero;
	sub = add = 0;
	target = get_random_text_addr();
	kallsyms_lookup(target, &end, &offset, NULL, namebuf);
	target -= offset;
	end += target;
	memset(namebuf, 0, 256);

	while (target < end){
		next = do_disasm(target, namebuf);
		if(!sub && !add && (sub = imm_subrsp(target) != -1)) {
			ret.low = target;
		} else if(sub && !add && (add = imm_addrsp(target) != -1)) {
			ret.high = target;
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
	return u128_zero;
}

static int is_testraxrax(unsigned long addr)
{
	u8 * p = (u8 *)addr;
	size_t byte = do_disasm(addr, NULL);
	if (byte == 3 && *p++ == 0x48 && *p++ == 0x85 && *p++ == 0xc0)
		return 1;
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

static u128 get_null(void)
{
	u128 zero = {.low=0, .high = 0};
	return zero;
}

static u128 get_nullcheck(void)
{
    unsigned long target;
	unsigned long test = 0;
	unsigned long next;
	u128 u128_zero = {.low=0, .high=0};
	u128 ret = u128_zero;
	int i = 0;

	target = get_random_text_addr();

	while (1){
		next = do_disasm(target, NULL);
		if (i++ > 10000)
			return u128_zero;
		if(!test && is_testraxrax(target)){
			test = target;
			continue;
		}
		if(test && is_jejne(target)) {
			ret.low = test;
			ret.high = target;
			return ret;
		} else if (is_branch(target)) {
			return u128_zero;
		}
		target += next;
	}
	return u128_zero;
}

static void result_text2(struct swifi_result2 * res)
{
    unsigned long offset;
    char * namebuf;
    
    namebuf = kzalloc(256, GFP_KERNEL);
    if (!namebuf)
        return;
	kallsyms_lookup(res->target.low, NULL, &offset, NULL, namebuf);
    snprintf(res->str, 100, "symbol:%s+0x%lx", namebuf, offset);
    do_disasm((bfd_vma)&res->old_content, res->old_instr);
    do_disasm((bfd_vma)&res->new_content, res->new_instr);
	
	memset(namebuf, 0, 256);

	kallsyms_lookup(res->target.high, NULL, &offset, NULL, namebuf);
    snprintf(res->str2, 100, "symbol:%s+0x%lx", namebuf, offset);
    do_disasm((bfd_vma)&res->old_content2, res->old_instr2);
    do_disasm((bfd_vma)&res->new_content2, res->new_instr2);
    
	kfree(namebuf);
}

static void result_nothing(struct swifi_result2 * res)
{
    snprintf(res->str, 100, "nothing to do");
	snprintf(res->str2, 100, "nothing to do");
}

struct swifi_op2 {
    int cmd;
    u128 (*inject_fault)(unsigned long, size_t);
	u128 (*inject_fault2)(unsigned long, size_t);
    u128 (*get_target)(void);
    void (*result_report)(struct swifi_result2 *);
};

static struct swifi_op2 sop[] = {
    {SWIFI_VAR,        do_mulimm,     do_mulimm,    get_var,        result_text2},
    {SWIFI_NULL,       do_compraxrax,   do_inverse,     get_nullcheck,  result_text2},
    {SWIFI_TEST_VAR,        test_do_mulimm,     test_do_mulimm,    get_var,        result_text2},
    {SWIFI_TEST_NULL,       test_do_compraxrax,   test_do_inverse,     get_nullcheck,  result_text2},
/* add new swifi_op from this line */
    {SWIFI_DONOTHING2, do_nothing, do_nothing,  get_null,       result_nothing}
};

long do_swifi2(int cmd, struct swifi_result2 __user * result)
{
    int ret = -1;
	size_t byte, byte2;
    struct swifi_op2 * op;
	struct swifi_result2 * res = kzalloc(sizeof(struct swifi_result2), GFP_KERNEL);
	
    if (!res)
        return -1;

    op = &sop[(cmd < SWIFI_DONOTHING2)?cmd:SWIFI_DONOTHING2];
	res->target = op->get_target();
    if (probe_kernel_read(&res->old_content, (u128 *)res->target.low, sizeof(u128)) ||
	    probe_kernel_read(&res->old_content2, (u128 *)res->target.high, sizeof(u128)))
		goto final;

    if (__kernel_text_address(res->target.low) &&
		__kernel_text_address(res->target.high)) {
        byte = do_disasm((unsigned long)&res->old_content, NULL);
		byte2 = do_disasm((unsigned long)&res->old_content2, NULL);
        if (byte > sizeof(u128) || byte2 > sizeof(u128))
            goto final;
    } else 
		goto final;

	res->new_content = op->inject_fault(res->target.low, byte);
	res->new_content2 = op->inject_fault2(res->target.high, byte2);
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
