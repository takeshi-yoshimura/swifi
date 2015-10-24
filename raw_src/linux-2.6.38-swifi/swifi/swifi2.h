/*
 *  swifi.h
 *
 *  Created on: Feb 20, 2012
 *      Author: Takeshi Yoshimura
 */

#ifndef SWIFI2_H_
#define SWIFI2_H_

#include "swifi.h"

enum SWIFI2_CMD {
    SWIFI_VAR = 0,
	SWIFI_NULL,
	SWIFI_TEST_VAR,
	SWIFI_TEST_NULL,
    SWIFI_DONOTHING2
};

struct swifi_result2 {
	u128 target;
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
