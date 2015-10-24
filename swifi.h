#ifndef SWIFI_H_
#define SWIFI_H_

#include <asm/unistd.h>

enum SWIFI_CMD {
    SWIFI_TEXT = 0,
    SWIFI_STACK,
    SWIFI_HEAP,
    SWIFI_DATA,
    SWIFI_BSS,
    SWIFI_BRANCH,
    SWIFI_INVERSE,
    SWIFI_PTR,
    SWIFI_DSTSRC,
    SWIFI_INTERFACE,
    SWIFI_INIT,
    SWIFI_OFFBYONE,
    SWIFI_ALLOC,
    SWIFI_FREE,
    SWIFI_SIZE,
    SWIFI_BCOPY,
    SWIFI_LOOP,
    SWIFI_IRQ,
    SWIFI_TEST_TEXT,
    SWIFI_TEST_STACK,
    SWIFI_TEST_HEAP,
    SWIFI_TEST_DATA,
    SWIFI_TEST_BSS,
    SWIFI_TEST_BRANCH,
    SWIFI_TEST_INVERSE,
    SWIFI_TEST_PTR,
    SWIFI_TEST_DSTSRC,
    SWIFI_TEST_INTERFACE,
    SWIFI_TEST_INIT,
    SWIFI_TEST_OFFBYONE,
    SWIFI_TEST_ALLOC,
    SWIFI_TEST_FREE,
    SWIFI_TEST_SIZE,
    SWIFI_TEST_BCOPY,
    SWIFI_TEST_LOOP,
    SWIFI_TEST_IRQ,
    SWIFI_VAR,
    SWIFI_NULL,
    SWIFI_NEWIRQ,
    SWIFI_TEST_VAR,
    SWIFI_TEST_NULL,
    SWIFI_TEST_NEWIRQ,
    SWIFI_DONOTHING
};

#define sys_swifi(str, cmd, sed, res) syscall(400, str, cmd, sed, res)
#define sys_swifi2(str, cmd, sed, res) syscall(401, str, cmd, sed, res)

#ifdef __x86_64__
typedef struct u128 {
    unsigned long low;
    unsigned long high;
}u128;
#elif __i386__
typedef struct u128 {
    unsigned long long low;
    unsigned long long high;
}u128;
#endif

typedef struct addrs {
    unsigned long addr1;
    unsigned long addr2;
}addrs;

struct swifi_result {
    unsigned long target;
    u128 old_content;
    u128 new_content;
    char str[100];
    char old_instr[256];
    char new_instr[256];
};

struct swifi_result2 {
    addrs target;
    u128 old_content;
    u128 new_content;
    u128 old_content2;
    u128 new_content2;
    char str[100];
    char str2[100];
    char old_instr[256];
    char new_instr[256];
    char old_instr2[256];
    char new_instr2[256];
};

#endif
