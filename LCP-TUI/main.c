#include "lcpexecute.h"
#include "lcpfindtest.h"
#include "lcpheader.h"
#include <stdio.h>
#include <stdlib.h>
#include <ncurses.h>

int main() {
    int choice = 0;
    int max_choice = 3;
    int key;
    int i;
    
    initscr();
    cbreak();
    echo();
    keypad(stdscr,TRUE);
    scrollok(stdscr,TRUE);
    
    while(1) {
        clear();
        printw("====Main Menu===\n");
        for (i = 1; i <= max_choice; i++) {
            if (i == choice) {
                attron(A_REVERSE);
                printw("-> ");
            }
            printw("%d. ", i);
            if (i == 1) {
                printw("Libpcap\n");
            } else if (i == 2) {
                printw("Libnids\n");
            } else if (i == 3) {
                printw("Exit\n");
            }
            if (i == choice) {
                attroff(A_REVERSE);
            }
        }
        refresh();
        key = getch();
        if (key == KEY_UP) {  
            choice--;
        if (choice < 1) {
                choice = max_choice;
            }
        } else if (key == KEY_DOWN) {  
            choice++;
            if (choice > max_choice) {
                choice = 1;
            }
        } else if (key == '\n') {
            switch (choice) {
                case 1:
                    printw("选择了使用Libpcap\n");
                    execute();
                    break;
                case 2:
                    printw("Libnids is not a valueable choice,sorry.\n");
                    break;
                case 3:
                    printw("Will exit soon.\n");
                    break;
                default:
                    printw("No useful choice\n");
                    break;
            }
            break;
        }
    }
    refresh();
    getch();

    endwin();  // 关闭Ncurses
    }