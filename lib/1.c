#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGTH 100

int main() {
    FILE *fp;
    char line[MAX_LINE_LENGTH];
    char config_path[] = "config.txt";
    char string1[MAX_LINE_LENGTH];
    int condition;[MAX_LINE_LENGTH];
    char rule[MAX_LINE_LENGTH];

    fp = fopen(config_path, "r");

    if (fp == NULL) {
        fprintf(stderr, "Error opening file: %s\n", config_path);
        exit(EXIT_FAILURE);
    }

    while (fgets(line, MAX_LINE_LENGTH, fp) != NULL) {
        // get the first string variable
        if (strstr(line, "devStr=") != NULL) {
            sscanf(line, "devStr=%s", string1);
        }
        if (strstr(line,"rule=")!=NULL){
            sscanf(line,"rule=%s",rule);
        }
        // get the second string variable
        if (strstr(line,"condition=")!=NULL){
            sscanf(line,"condition=%s",condition);
        }
    }

    fclose(fp);

    printf("string1: %s\n", string1);
    printf("condition: %d\n", condition);
    printf("rule:%s\n",rule);

    return 0;
}