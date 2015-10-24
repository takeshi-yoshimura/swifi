/*
 * swifi.c -- a user support tool for fault injection in linux
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

#include <stdio.h>
#include <stdlib.h>
#include "swifi.h"

int main(int argc, char *argv[])
{
    unsigned long cmd, seed;
    struct swifi_result result;
    struct swifi_result2 result2;

    if (argc != 4 || (argc >= 2 && !strcmp(argv[1], "-h")))
        goto help;

    cmd = atol(argv[2]);
    seed = atol(argv[3]);
    if (seed == 0)
        goto help;

    if (cmd < SWIFI_VAR) {	
        if (sys_swifi(argv[1], cmd, seed, &result) == -1) {
            return -1;
        }
        printf("cmd = %2d seed = %d\n", cmd, seed);
        printf("target address: %lx (%s)\n", result.target, result.str);
        printf("change content from %016lx %016lx to %016lx %016lx\n", 
            result.old_content.low, result.old_content.high, result.new_content.low, result.new_content.high);
        printf("old instruction: %s\n", result.old_instr);
        printf("new instruction: %s\n", result.new_instr);
    } else if (SWIFI_VAR <= cmd && cmd < SWIFI_DONOTHING) {
        cmd -= SWIFI_VAR;
        if (sys_swifi2(argv[1], cmd, seed, &result2) == -1) {
            return -1;
        }
        printf("cmd = %2d seed = %d\n", cmd, seed);
        printf("target address: %lx (%s)\n", result2.target.addr1, result2.str);
        printf("change content from %016lx %016lx to %016lx %016lx\n", 
            result2.old_content.low, result2.old_content.high, result2.new_content.low, result2.new_content.high);
        printf("old instruction: %s\n", result2.old_instr);
        printf("new instruction: %s\n\n", result2.new_instr);

        printf("target address2: %lx (%s)\n", result2.target.addr2, result2.str2);
        printf("change content from %016lx %016lx to %016lx %016lx\n", 
            result2.old_content2.low, result2.old_content2.high, result2.new_content2.low, result2.new_content2.high);
        printf("old instruction2: %s\n", result2.old_instr2);
        printf("new instruction2: %s\n", result2.new_instr2);
        cmd += SWIFI_VAR;
    }

    return 0;
help:
    printf("usage: %s $target $cmd $seed\n", argv[0]);
    printf("$cmd\n");
    printf("TEXT=%d,STACK=%d,HEAP=%d,DATA=%d,BSS=%d\n",
        SWIFI_TEXT,SWIFI_STACK,SWIFI_HEAP,SWIFI_DATA,SWIFI_BSS);
    printf("BRANCH=%d,INVERSE=%d,PTR=%d,DSTSRC=%d\n",
        SWIFI_BRANCH,SWIFI_INVERSE,SWIFI_PTR,SWIFI_DSTSRC);
    printf("INTERFACE=%d,INIT=%d,OFFBYONE=%d,ALLOC=%d\n",
        SWIFI_INTERFACE,SWIFI_INIT,SWIFI_OFFBYONE,SWIFI_ALLOC);
    printf("FREE=%d,SIZE=%d,BCOPY=%d,LOOP=%d\n",
        SWIFI_FREE,SWIFI_SIZE, SWIFI_BCOPY, SWIFI_LOOP);
    printf("IRQ=%d,VAR=%d,NULL=%d,NEWIRQ=%d\n\n",
        SWIFI_IRQ,SWIFI_VAR,SWIFI_NULL,SWIFI_NEWIRQ);

    printf("TEST_TEXT=%d,TEST_STACK=%d,TEST_HEAP=%d,TEST_DATA=%d,TEST_BSS=%d\n",
        SWIFI_TEST_TEXT,SWIFI_TEST_STACK,SWIFI_TEST_HEAP,SWIFI_TEST_DATA,SWIFI_TEST_BSS);
    printf("TEST_BRANCH=%d,TEST_INVERSE=%d,TEST_PTR=%d,TEST_DSTSRC=%d\n",
        SWIFI_TEST_BRANCH,SWIFI_TEST_INVERSE,SWIFI_TEST_PTR,SWIFI_TEST_DSTSRC);
    printf("TEST_INTERFACE=%d,TEST_INIT=%d,TEST_OFFBYONE=%d,TEST_ALLOC=%d\n",
        SWIFI_TEST_INTERFACE,SWIFI_TEST_INIT,SWIFI_TEST_OFFBYONE,SWIFI_TEST_ALLOC);
    printf("TEST_TEST_FREE=%d,TEST_SIZE=%d,TEST_BCOPY=%d,TEST_LOOP=%d\n",
        SWIFI_TEST_FREE,SWIFI_TEST_SIZE,SWIFI_TEST_BCOPY,SWIFI_TEST_LOOP);
    printf("TEST_IRQ=%d,TEST_VAR=%d,TEST_NULL=%d,TEST_NEWIRQ=%d\n",
        SWIFI_TEST_IRQ,SWIFI_TEST_VAR,SWIFI_TEST_NULL,SWIFI_TEST_NEWIRQ);
    return 0;
}
