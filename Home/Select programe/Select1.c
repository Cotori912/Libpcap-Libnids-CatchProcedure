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
    printf("⣿⣿⣿⠟⠛⠛⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⢋⣩⣉⢻           基于Libpcap和Libnids库的网络流量抓包软件\n");
    sleep(0.5);
    printf("⣿⣿⣿⠀⣿⣶⣕⣈⠹⠿⠿⠿⠿⠟⠛⣛⢋⣰⠣⣿⣿⠀⣿                      作者：张希尧\n");
    sleep(0.5);
    printf("⣿⣿⣿⡀⣿⣿⣿⣧⢻⣿⣶⣷⣿⣿⣿⣿⣿⣿⠿⠶⡝⠀⣿             可执行的功能 自定义捕获的网卡\n");
    sleep(0.5);
    printf("⣿⣿⣿⣷⠘⣿⣿⣿⢏⣿⣿⣋⣀⣈⣻⣿⣿⣷⣤⣤⣿⡐⢿                          自定义保存的路径 \n");
    sleep(0.5);
    printf("⣿⣿⣿⣿⣆⢩⣝⣫⣾⣿⣿⣿⣿⡟⠿⠿⠦⠀⠸⠿⣻⣿⡄⢻                         自定义捕获模式 \n");
    sleep(0.5);
    printf("⣿⣿⣿⣿⣿⡄⢻⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣾⣿⣿⣿⣿⠇⣼                         自定义离线读取路径\n");
    sleep(0.5);
    printf("⣿⣿⣿⣿⣿⣿⡄⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣰                          自定义捕获包的类型\n");
    sleep(0.5);
    printf("⣿⣿⣿⣿⣿⣿⠇⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢀⣿\n");
    printf("⣿⣿⣿⣿⣿⠏⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢸⣿.        如果需要修改参数请前往配置文件config.txt修改\n");
    sleep(0.5);
    printf("⣿⣿⣿⣿⠟⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣿.\n");
    sleep(0.5);
    printf("⣿⣿⣿⠋⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⣿.\n");
    sleep(0.5);
    printf("⣿⣿⠋⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸.\n"
 );

    sleep(3);
    printf("Choose a program to run:\n");
    printf("1. Libpcap\n");
    printf("2. Libnids\n");
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