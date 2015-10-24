/*
 * kdisasm.c -- a user support tool for disassembling running linux
 *
 * Copyright (c) 2013 Takeshi Yoshimura
 *
 * The source code in this file can be freely used, adapted,
 * and redistributed in source or binary form, so long as an
 * acknowledgment appears in derived source files.  No warranty 
 * is attached; we cannot take responsibility for errors or 
 * fitness for use.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <asm/unistd_64.h>

#define sys_disasm(addr, str) syscall(402, addr, str)

int main(int argc, char *argv[])
{
	char str[256];
	char prev_str[256];
	unsigned long addr, tmp;
	int i,j;

	if (argc != 2)
		return -1;
	addr = strtoul(argv[1], NULL, 16);

	if (addr == 0)
		return -1;

	memset(prev_str, 0, 256);
	tmp = sys_disasm(addr, prev_str);
	if (tmp == -1) {
		printf("cannot disassemble at %lx\n", addr);
		return -1;
	}
	printf ("%s\n", prev_str);
	
	addr += tmp;
	while (1) {
		memset(str, 0, 256);
		tmp = sys_disasm(addr, str);
		if (tmp == -1) {
			printf("cannot disassemble at %lx\n",addr);
			return -1;
		}
		//finish disassembling if the symbol name is changed
		for (i = 19; i < 256 - 1; i++) {
			if (str[i] != prev_str[i])
				return 0;
			if (str[i+1] == ':' || str[i+1] == '+' )
				break;
		}
		addr += tmp;
		printf("%s\n", str);
		memset(prev_str, 0, 256);
		strncpy(prev_str, str, 256);
	}
	return 0;
}
