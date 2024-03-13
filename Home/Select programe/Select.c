#include <stdio.h>
#include <stdlib.h>

void program1() {
    printf("Running Program 1...\n");
    // 在这里编写程序1的代码
}

void program2() {
    printf("Running Program 2...\n");
    // 在这里编写程序2的代码
}

int main() {
    int choice;

    printf("Choose a program to run:\n");
    printf("1. Program 1\n");
    printf("2. Program 2\n");
    printf("Enter your choice: ");
    scanf("%d", &choice);

    switch (choice) {
        case 1:
            program1();
            break;
        case 2:
            program2();
            break;
        default:
            printf("Invalid choice.\n");
            exit(1);
    }

    return 0;
}