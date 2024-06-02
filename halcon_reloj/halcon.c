#include "halcon.h"

int main(int argc,char** argv)
{
    initscr();
    clear();
    WINDOW *w1,*w2,*w3,*w4,*w5,*w6,*w7,*w8,*w9,*w10;
    w1=newwin(12,7,5,5);
    w2=newwin(12,7,5,14);
    w3=newwin(12,7,5,23);
    w4=newwin(12,7,5,32);
    w5=newwin(12,7,5,41);
    w6=newwin(12,7,5,50);
    w7=newwin(12,7,5,59);
    w8=newwin(12,7,5,68);
    w9=newwin(2,25,22,53);
    w10=newwin(2,25,22,5);

    const char* chupacabra="PRODUCED BY CHUPACABRA";
    char date[STRING_SIZE];

    if(!has_colors())
    {
        endwin();
        fprintf(stderr,"The colors aren't supported.\n");
        exit(EXIT_FAILURE);
    }
    start_color();
    init_pair(1,COLOR_BLUE,COLOR_BLACK);
    init_pair(2,COLOR_YELLOW,COLOR_BLACK);

    char str[STRING_SIZE];
    char colon[STRING_SIZE];

    int array[TIME_SIZE];
    struct tm* time_st;
    time_t current_time;
    int counter=0;

    while(TRUE)
    {
        wclear(stdscr);
        wclear(w1);
        wclear(w2);
        wclear(w3);
        wclear(w4);
        wclear(w5);
        wclear(w6);
        wclear(w7);
        wclear(w8);
        wclear(w9);
        wclear(w10);
        curs_set(0);

        current_time=time(NULL);
        time_st=localtime(&current_time);
        set_time(array,time_st);
        set_date(time_st,date);

        print_number(array[0],str);
        wattrset(w1,A_BOLD);
        wprintw(w1,"%s",str);

        print_number(array[1],str);
        wattrset(w2,A_BOLD);
        wprintw(w2,"%s",str);

        print_number(array[2],str);
        wattrset(w4,A_BOLD);
        wprintw(w4,"%s",str);

        print_number(array[3],str);
        wattrset(w5,A_BOLD);
        wprintw(w5,"%s",str);

        print_number(array[4],str);
        wattrset(w7,A_BOLD);
        wprintw(w7,"%s",str);

        print_number(array[5],str);
        wattrset(w8,A_BOLD);
        wprintw(w8,"%s",str);

        if(counter>=5)
        {
            memset(colon,0,STRING_SIZE);
            counter++;
        }
        if(counter<5)
        {
            print_colon(colon);
            counter++;
        }
        if(counter==10) counter=0;
        wattrset(w3,COLOR_PAIR(1));
        wprintw(w3,"%s",colon);
        wattrset(w6,COLOR_PAIR(1));
        wprintw(w6,"%s",colon);
        wattrset(w9,COLOR_PAIR(2));
        wprintw(w9,"%s\n",chupacabra);
        wattrset(w10,COLOR_PAIR(2));
        wprintw(w10,"%s",date);
        wmove(stdscr,19,30);
        wattrset(stdscr,COLOR_PAIR(1));
        wprintw(stdscr,"Press Ctrl-C to quit");

        wnoutrefresh(stdscr);
        wnoutrefresh(w1);
        wnoutrefresh(w2);
        wnoutrefresh(w3);
        wnoutrefresh(w4);
        wnoutrefresh(w5);
        wnoutrefresh(w6);
        wnoutrefresh(w7);
        wnoutrefresh(w8);
        wnoutrefresh(w9);
        wnoutrefresh(w10);
        doupdate();
        usleep(100000);
    }

    endwin();
    return 0;
}