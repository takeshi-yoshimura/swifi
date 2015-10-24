/*
 *  disasm.c - disassembling the x86 Linux kernel text
 *  Created on: Feb 11, 2012
 *      Author: Takeshi Yoshimura
 *  note: the disassembler for x86_32 is under construction
 */

#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <asm/uaccess.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/slab.h>
#include"dis-asm.h"

disassemble_info info;
char disasm_buf[256];
char * ptr;

static int dis_fprintf(PTR file, const char *fmt, ...)
{
	char * buffer = kzalloc(256, GFP_KERNEL);
	va_list ap;

	va_start(ap, fmt);
	vsprintf(buffer, fmt, ap);
	va_end(ap);

	strncpy(ptr, buffer, 256 - strlen(disasm_buf));
	ptr += strlen(buffer);

    kfree(buffer);
	return 0;
}

static int dis_getmem(bfd_vma addr, bfd_byte *buf, unsigned int length, disassemble_info *dip)
{
	memcpy(buf, (void *)addr, length);
	return 0;
}

static void dis_printaddr_flg(bfd_vma addr, disassemble_info *dip, int flag)
{
	unsigned long sym_offset;
	char * sym_name = kzalloc(256, GFP_KERNEL);
	int spaces = 5;

	/*
	 * Print a symbol name or address as necessary.
	 */
	kallsyms_lookup(addr, NULL, &sym_offset, NULL, sym_name);

	if (sym_name[0] != '\0') {
		dip->fprintf_func(dip->stream,"0x%0*lx %s",(int)(2*sizeof(addr)), addr, sym_name); 
		if (sym_offset == 0) {
			spaces += 4;
		}
		else {
			unsigned long o = sym_offset;
			while (o >>= 4)
				--spaces;
			dip->fprintf_func(dip->stream,"+0x%x", sym_offset);
		}
	} else {
		dip->fprintf_func(dip->stream,"0x%lx", addr);
	}
	if (flag) {
		if (spaces < 1) {
			spaces = 1;
		}
		dip->fprintf_func(dip->stream, ":%*s", spaces, " ");
	}
    kfree(sym_name);
}

static void dis_printaddr(bfd_vma addr, disassemble_info *dip)
{
	dis_printaddr_flg(addr, dip, 0);
}

long do_disasm(bfd_vma address, char * str){
	long result;


#if defined(CONFIG_X86_64)
	info.disassembler_options	= "x86-64";
	info.mach					= bfd_mach_x86_64;
#elif defined(CONFIG_X86_32)
    info.disassembler_options   = "i386";
    info.mach                   = bfd_mach_i386_i386;
#endif
	info.print_address_func     = dis_printaddr;
	info.fprintf_func			= dis_fprintf;
	info.read_memory_func		= dis_getmem;

	info.flavour                = bfd_target_elf_flavour;
	info.arch				    = bfd_arch_i386;
	info.endian	    		    = BFD_ENDIAN_LITTLE;
	info.display_endian         = BFD_ENDIAN_LITTLE;
	
	info.stream					= NULL;
	info.application_data		= NULL;
	info.symbols				= NULL;
	info.num_symbols			= 0;
	info.flags					= 0;
	info.private_data			= NULL;
	info.buffer					= NULL;
	info.buffer_vma				= 0;
	info.buffer_length			= 0;
	info.bytes_per_line			= 0;
	info.bytes_per_chunk		= 0;
	info.insn_info_valid		= 0;
	info.branch_delay_insns		= 0;
	info.data_size				= 0;
	info.insn_type				= 0;
	info.target					= 0;
	info.target2				= 0;
	
	ptr = disasm_buf;
	memset(disasm_buf, 0, 256);
	
	dis_printaddr_flg(address, &info, 1);
	result = print_insn_i386_att(address, &info);
	if(str != NULL) {
		strncpy(str, disasm_buf, 256);
	}
	ptr = disasm_buf;
	memset(disasm_buf, 0, 256);
	return result;
}

SYSCALL_DEFINE2(disasm, unsigned long, address, char __user *, str){
    char * str2 = kzalloc(256, GFP_KERNEL);
    long ret = do_disasm(address, str2);
    if (ret > 0)
        copy_to_user(str, str2, 256);
    kfree(str2);
	return ret;
}
EXPORT_SYMBOL(sys_disasm);

