/*
 * adder.c - a minimal CGI program that adds two numbers together
 */
/* $begin adder */
#include "../csapp.h"

#define cave 0x0401296

unsigned int run_simulator(){
    printf("Flag{congratulation_you_get_the_flag}\n");
    printf("u stupid hacker\n");
}



void add_simulator(unsigned int a, unsigned int b){
    mprotect(0x401000, 0x1000, 7 );
    *(char*)(cave) = 0xb8;
	*(int*)(cave+1) = a;
	*(char*)(cave+5) = 0x05;
	*(int*)(cave+6) = b;
	*(char*)(cave+10) = 0xc3;
	mprotect((void*)0x401000, 0x1000, PROT_READ | PROT_EXEC);
}

int main(void) {
    char *buf, *p;
    char arg1[128], arg2[128], content[512];
    unsigned int n[3] = {0, 0, 0};

    /* Extract the two arguments */
    if ((buf = getenv("QUERY_STRING")) != NULL) {
        if(strncmp(buf, "ping", 4) == 0){
            system("ping -c 5 8.8.8.8");
            printf("Connection: close\r\n");
            printf("Content-type: text/html\r\n\r\n");
            fflush(stdout);
            return 0;
        }
        for(n[2] = 0; ; n[2]+=1){
            p = strchr(buf, '&');
            if(p == NULL) break;
            *p = '\0';
            strcpy(arg1, buf);
            strcpy(arg2, p+1);
            sscanf(arg1, "%u", &n[n[2]]);
            sscanf(arg2, "%u", &n[n[2]+1]);    
            buf = p+1;
        }
    }

    add_simulator(n[0], n[1]);
    unsigned int result = run_simulator();

    /* Make the response body */
    sprintf(content, "Welcome to add.com: ");
    sprintf(content, "%sTHE Internet addition portal.\r\n<p>", content);
    sprintf(content, "%sThe answer is: %d + %d = %d\r\n<p>", 
	    content, n[0], n[1], result);
    sprintf(content, "%sThanks for visiting!\r\n", content);
  
    /* Generate the HTTP response */
    printf("Connection: close\r\n");
    printf("Content-length: %d\r\n", (int)strlen(content));
    printf("Content-type: text/html\r\n\r\n");
    printf("%s", content);
    fflush(stdout);

    return 0;
}


/* $end adder */
