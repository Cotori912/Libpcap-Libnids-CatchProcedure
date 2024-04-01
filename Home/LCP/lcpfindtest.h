#ifndef __LCPFINDTEST_H__
#define __LCPFINDTEST_H__
#include <stdio.h>
#define MAX_LINE_LENGTH 100

extern FILE *fp;
extern char line[MAX_LINE_LENGTH];
extern char config_path[];
extern char devStr[MAX_LINE_LENGTH];
extern char path[MAX_LINE_LENGTH];
extern char condition[MAX_LINE_LENGTH];
extern char rule[MAX_LINE_LENGTH];


void findnet();

void autotest();

void handtest(char devStr[], char path[], char condition[], char rule[]);

#endif