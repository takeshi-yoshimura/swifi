/*
 * test_swifi.c -- a user support tool for fault injection in linux
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
#include "swifi.h"

int verify_swifi(int cmd, char * old_instr, char * new_instr)
{
    if (strstr(old_instr, "(bad)") || strstr(new_instr, "(bad)"))
        return 0;
    if (cmd == SWIFI_DSTSRC || cmd == SWIFI_TEST_DSTSRC ||
        cmd == SWIFI_PTR    || cmd == SWIFI_TEST_PTR) {
            char * p = &old_instr[19];
            char * q = &new_instr[19];
            for (;*p != '%' && *p != '$' && *p != '0' && *p != '-'; p++, q++) {
                if (*p != *q)
                    return 0;
            }
    }
    return 1;
}

int swifi_result_equal(struct swifi_result * res1, struct swifi_result * res2)
{
    return ((res1->target == res2->target) &&
        (res1->old_content.low == res2->old_content.low) &&
        (res1->old_content.high == res2->old_content.high) &&
        (res1->old_content.low == res2->old_content.low) &&
        (res1->new_content.high == res2->new_content.high));
}

int swifi_result2_equal(struct swifi_result2 * res1, struct swifi_result2 * res2)
{
    return ((res1->target.addr1 == res2->target.addr1) &&
        (res1->target.addr2 == res2->target.addr2) &&
        (res1->old_content.low == res2->old_content.low) &&
        (res1->old_content.high == res2->old_content.high) &&
        (res1->old_content.low == res2->old_content.low) &&
        (res1->new_content.high == res2->new_content.high));
}

int seq_swifi(char * target, int cmd, int NUM_FAULT)
{
    long seed, i, fail, count;

    int j;

    seed = cmd + 100;
    count = fail = 0;

    if (cmd < SWIFI_VAR) {
        struct swifi_result * res = calloc(NUM_FAULT, sizeof(struct swifi_result));
        long * sed = calloc(NUM_FAULT, sizeof(long));
        struct swifi_result tmp;
        for (seed = cmd, i = 0; i < NUM_FAULT; i++) {
            seed += i * 100;
            memset(&tmp, 0, sizeof(struct swifi_result));
            if (sys_swifi(target, cmd, seed, &tmp) == -1) {
                seed += 100;
                if (fail++ >= NUM_FAULT) {
                    printf("Too many errors! Module name and fault number is correct? Otherwise, set number of fault tests smaller or larger\n");
                    break;
                }
                if (i > 0)
                    i--;
            } else {
                if (!verify_swifi(cmd, tmp.old_instr, tmp.new_instr)) {
                    printf("Maybe Incorrect: %s %s\n", tmp.old_instr, tmp.new_instr);
                    continue;
                }
                for (j = 0; j < i; j++) {
                    if (swifi_result_equal(&tmp, &res[j])) {
                        break;
                    }
                }
                if (j == i && count < NUM_FAULT) {
                    res[count] = tmp;
                    sed[count++] = seed;
                }
            }
        }
        printf("cmd = %2d, specified num = %3d, total = %d\n", cmd, NUM_FAULT, count);
        for (i = 0; i < count; i++) {
            printf("-------------------------------------------------------\n");
            printf("number:%3d seed: %d\n", i, sed[i]);
            printf("target address: %lx (%s)\n", res[i].target, res[i].str);
            printf("change content from %016lx %016lx to %016lx %016lx\n", 
                res[i].old_content.low, res[i].old_content.high, res[i].new_content.low, res[i].new_content.high);
            printf("old instruction:  %s\n", res[i].old_instr);
            printf("new instruction:  %s\n", res[i].new_instr);
        }
        free(res);
        free(sed);
    } else if (SWIFI_VAR <= cmd && cmd < SWIFI_DONOTHING) {
        struct swifi_result2 * res = calloc(NUM_FAULT, sizeof(struct swifi_result2));
        long * sed = calloc(NUM_FAULT, sizeof(long));
        struct swifi_result2 tmp;
        for (seed = cmd, i = 0; i < NUM_FAULT; i++) {
            seed += i * 100;
            memset(&tmp, 0, sizeof(struct swifi_result2));
            if (sys_swifi2(target, cmd - SWIFI_VAR, seed, &tmp) == -1) {
                seed += 100;
                if (fail++ >= NUM_FAULT) {
                    printf("Too many errors! Module name and fault number is correct? Otherwise, set number of fault tests smaller or larger\n");
                    break;
                }
                if (i > 0)
                    i--;
            } else {
                if (!verify_swifi(cmd, tmp.old_instr, tmp.new_instr) ||
                    !verify_swifi(cmd, tmp.old_instr2, tmp.new_instr2))
                    continue;
                for (j = 0; j < i; j++) {
                    if (swifi_result2_equal(&tmp, &res[j])) {
                        break;
                    }
                }
                if (j == i && count < NUM_FAULT) {
                    res[count] = tmp;
                    sed[count++] = seed;
                }
            }
        }
        printf("cmd = %2d, specified num = %3d, total = %d\n", cmd, NUM_FAULT, count);
        for (i = 0; i < count; i++) {
            printf("-------------------------------------------------------\n");
            printf("number:%3d seed: %d\n", i, sed[i]);
            printf("target address: %lx (%s)\n", res[i].target.addr1, res[i].str);
            printf("change content from %016lx %016lx to %016lx %016lx\n", 
                res[i].old_content.low, res[i].old_content.high, res[i].new_content.low, res[i].new_content.high);
            printf("old instruction: %s\n", res[i].old_instr);
            printf("new instruction: %s\n\n", res[i].new_instr);

            printf("target address2: %lx (%s)\n", res[i].target.addr2, res[i].str2);
            printf("change content from %016lx %016lx to %016lx %016lx\n", 
                res[i].old_content2.low, res[i].old_content2.high, res[i].new_content2.low, res[i].new_content2.high);
            printf("old instruction2: %s\n", res[i].old_instr2);
            printf("new instruction2: %s\n", res[i].new_instr2);
        }
        free(res);
    } else {
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    unsigned long cmd, seed, num_fault;

    if (argc != 4 || (argc >= 2 && !strcmp(argv[1], "-h")))
        goto help;

    cmd = atol(argv[2]);
    num_fault = atol(argv[3]);

    if ((SWIFI_TEXT <= cmd) && (cmd <= SWIFI_IRQ) || ((SWIFI_VAR <= cmd) && (cmd <= SWIFI_NEWIRQ))){
        printf("cmd = %s, number of faults= %s. please specify TEST_* command\n", argv[2], argv[3]);
        return -1;
    }

    return seq_swifi(argv[1], cmd, num_fault);
help:
    printf("usage: %s <module name> <cmd> <number of verifying faults>\n", argv[0]);
    printf("$cmd\n");
    printf("TEXT=%d,STACK=%d,HEAP=%d,DATA=%d,BSS=%d\n",
        SWIFI_TEST_TEXT,SWIFI_TEST_STACK,SWIFI_TEST_HEAP,SWIFI_TEST_DATA,SWIFI_TEST_BSS);
    printf("BRANCH=%d,INVERSE=%d,PTR=%d,DSTSRC=%d\n",
        SWIFI_TEST_BRANCH,SWIFI_TEST_INVERSE,SWIFI_TEST_PTR,SWIFI_TEST_DSTSRC);
    printf("INTERFACE=%d,INIT=%d,OFFBYONE=%d,ALLOC=%d\n",
        SWIFI_TEST_INTERFACE,SWIFI_TEST_INIT,SWIFI_TEST_OFFBYONE,SWIFI_TEST_ALLOC);
    printf("FREE=%d,SIZE=%d,BCOPY=%d,LOOP=%d\n",
        SWIFI_TEST_FREE,SWIFI_TEST_SIZE, SWIFI_TEST_BCOPY, SWIFI_TEST_LOOP);
    printf("IRQ=%d,VAR=%d,NULL=%d,NEWIRQ=%d\n",
        SWIFI_TEST_IRQ,SWIFI_TEST_VAR,SWIFI_TEST_NULL,SWIFI_TEST_NEWIRQ);
    return 0;
}
