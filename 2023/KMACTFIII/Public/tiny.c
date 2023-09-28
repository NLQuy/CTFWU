/* $begin tinymain */
/*
 * tiny.c - A simple, iterative HTTP/1.0 Web server that uses the 
 *     GET method to serve static and dynamic content.
 */
#include "csapp.h"
#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <string.h>
#include <stdio.h>

typedef struct tiny_cookie{
    char *name;
    char *value;
    struct tiny_cookie *next;
} tiny_cookie;

tiny_cookie *cookie_head = NULL;

char *cookie_string = NULL;
char *hash = NULL;

void doit(int fd);
void read_requesthdrs(rio_t *rp);
int parse_uri(char *uri, char *filename, char *cgiargs);
void serve_static(int fd, char *filename, int filesize);
void get_filetype(char *filename, char *filetype);
void serve_dynamic(int fd, char *filename, char *cgiargs);
void clienterror(int fd, char *cause, char *errnum, 
		 char *shortmsg, char *longmsg);
void parse_cookie(char *cookie, tiny_cookie **cookie_head);
int authen(tiny_cookie *cookie_head);

int main(int argc, char **argv) 
{
    int listenfd, connfd;
    char hostname[MAXLINE], port[MAXLINE];
    socklen_t clientlen;
    struct sockaddr_storage clientaddr;

    /* Check command line args */
    if (argc != 2) {
	fprintf(stderr, "usage: %s <port>\n", argv[0]);
	exit(1);
    }

    listenfd = Open_listenfd(argv[1]);
    while (1) {
	clientlen = sizeof(clientaddr);
	connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen); //line:netp:tiny:accept
	doit(connfd);     
    // clean garbage
    tiny_cookie *ptr = cookie_head;
    while(ptr != NULL){
        tiny_cookie *tmp_ptr = ptr;
        ptr = ptr->next;
        free(tmp_ptr->name);
        free(tmp_ptr->value);
        free(tmp_ptr);
    }
    cookie_head = NULL;   
         
                             //line:netp:tiny:doit
	Close(connfd);                                            //line:netp:tiny:close
    }
}
/* $end tinymain */

/*
 * doit - handle one HTTP request/response transaction
 */
/* $begin doit */
void doit(int fd) 
{
    int is_static;
    struct stat sbuf;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char filename[MAXLINE], cgiargs[MAXLINE];
    rio_t rio;
    /* Read request line and headers */
    Rio_readinitb(&rio, fd);
    if (!Rio_readlineb(&rio, buf, MAXLINE))  //line:netp:doit:readrequest
        return;
    printf("%s", buf);
    sscanf(buf, "%s %s %s", method, uri, version);       //line:netp:doit:parserequest
    if (strcasecmp(method, "GET")) {                     //line:netp:doit:beginrequesterr
        clienterror(fd, method, "501", "Not Implemented",
                    "Tiny does not implement this method");
        return;
    }                                                    //line:netp:doit:endrequesterr
    read_requesthdrs(&rio);                              //line:netp:doit:readrequesthdrs

    /* Parse cookie to process authen after */
    if(cookie_string != NULL){
        // parse cookie to linked list and store head to cookie_head
        parse_cookie(cookie_string, &cookie_head);
    }



    /* Parse URI from GET request */
    is_static = parse_uri(uri, filename, cgiargs);       //line:netp:doit:staticcheck
    if (stat(filename, &sbuf) < 0) {                     //line:netp:doit:beginnotfound
	clienterror(fd, filename, "404", "Not found",
		    "Tiny couldn't find this file");
	return;
    }                                                    //line:netp:doit:endnotfound

    if (is_static) { /* Serve static content */          
	if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) { //line:netp:doit:readable
	    clienterror(fd, filename, "403", "Forbidden",
			"Tiny couldn't read the file");
	    return;
	}
	serve_static(fd, filename, sbuf.st_size);        //line:netp:doit:servestatic
    }
    else { /* Serve dynamic content */
	if (!(S_ISREG(sbuf.st_mode)) || !(S_IXUSR & sbuf.st_mode)) { //line:netp:doit:executable
	    clienterror(fd, filename, "403", "Forbidden",
			"Tiny couldn't run the CGI program");
	    return;
	}
    if(authen(cookie_head) == -1){
        // authen failed
        clienterror(fd, filename, "401", "Unauthorized",
            "Tiny couldn't authen the user");
        return;
    }
    // calculate hash to set cookie for client

	serve_dynamic(fd, filename, cgiargs);            //line:netp:doit:servedynamic

    }
}
/* $end doit */

/*
 * read_requesthdrs - read HTTP request headers
 */
/* $begin read_requesthdrs */
void read_requesthdrs(rio_t *rp) 
{
    char buf[MAXLINE];

    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);
    while(strcmp(buf, "\r\n")) {          //line:netp:readhdrs:checkterm
    if(strstr(buf, "Cookie:")){ //line:netp:readhdrs:readcookie 
        char *cookie = strstr(buf, "Cookie:");
        char *cookie_end = strstr(cookie, "\r\n");
        cookie_string = malloc(cookie_end - cookie);
        memset(cookie_string, 0, cookie_end - cookie);
        strncpy(cookie_string, cookie+8, cookie_end - cookie);
    }
    Rio_readlineb(rp, buf, MAXLINE);
	printf("%s", buf);
    }
    return;
}
/* $end read_requesthdrs */

/*
 * parse_uri - parse URI into filename and CGI args
 *             return 0 if dynamic content, 1 if static
 */
/* $begin parse_uri */
int parse_uri(char *uri, char *filename, char *cgiargs) 
{
    char *ptr;

    if (!strstr(uri, "cgi-bin")) {  /* Static content */ //line:netp:parseuri:isstatic
	    strcpy(cgiargs, "");                             //line:netp:parseuri:clearcgi
	    strcpy(filename, ".");                           //line:netp:parseuri:beginconvert1
	    strcat(filename, uri);                           //line:netp:parseuri:endconvert1
	    if (uri[strlen(uri)-1] == '/')                   //line:netp:parseuri:slashcheck
	        strcat(filename, "login.html");               //line:netp:parseuri:appenddefault
	    return 1;
    }
    else {  /* Dynamic content */                        //line:netp:parseuri:isdynamic
	    ptr = index(uri, '?');                           //line:netp:parseuri:beginextract
        if (ptr) {
	        strcpy(cgiargs, ptr+1);
	        *ptr = '\0';
	    }else 
	        strcpy(cgiargs, "");                         //line:netp:parseuri:endextract
	    strcpy(filename, ".");                           //line:netp:parseuri:beginconvert2
	    strcat(filename, uri);                           //line:netp:parseuri:endconvert2
	return 0;
    }
}
/* $end parse_uri */

/*
 * serve_static - copy a file back to the client 
 */
/* $begin serve_static */
void serve_static(int fd, char *filename, int filesize) 
{
    int srcfd;
    char *srcp, filetype[MAXLINE], buf[MAXBUF];
 
    /* Send response headers to client */
    get_filetype(filename, filetype);       //line:netp:servestatic:getfiletype
    sprintf(buf, "HTTP/1.0 200 OK\r\n");    //line:netp:servestatic:beginserve
    sprintf(buf, "%sServer: Tiny Web Server\r\n", buf);
    sprintf(buf, "%sConnection: close\r\n", buf);
    sprintf(buf, "%sContent-length: %d\r\n", buf, filesize);
    sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, filetype);
    Rio_writen(fd, buf, strlen(buf));       //line:netp:servestatic:endserve
    printf("Response headers:\n");
    printf("%s", buf);

    /* Send response body to client */
    srcfd = Open(filename, O_RDONLY, 0);    //line:netp:servestatic:open
    srcp = Mmap(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);//line:netp:servestatic:mmap
    Close(srcfd);                           //line:netp:servestatic:close
    Rio_writen(fd, srcp, filesize);         //line:netp:servestatic:write
    Munmap(srcp, filesize);                 //line:netp:servestatic:munmap
}

/*
 * get_filetype - derive file type from file name
 */
void get_filetype(char *filename, char *filetype) 
{
    if (strstr(filename, ".html"))
	strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif"))
	strcpy(filetype, "image/gif");
    else if (strstr(filename, ".png"))
	strcpy(filetype, "image/png");
    else if (strstr(filename, ".jpg"))
	strcpy(filetype, "image/jpeg");
    else
	strcpy(filetype, "text/plain");
}  
/* $end serve_static */

/*
 * serve_dynamic - run a CGI program on behalf of the client
 */
/* $begin serve_dynamic */
void serve_dynamic(int fd, char *filename, char *cgiargs) 
{
    char buf[MAXLINE], *emptylist[] = { NULL };

    /* Return first part of HTTP response */
    sprintf(buf, "HTTP/1.0 200 OK\r\n"); 
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Server: Tiny Web Server\r\nSet-Cookie: hash=%s\r\n", hash);
    Rio_writen(fd, buf, strlen(buf));
    if(hash != NULL){
        free(hash);
        hash = NULL;
    }   
    if (Fork() == 0) { /* Child */ //line:netp:servedynamic:fork
	/* Real server would set all CGI vars here */
	setenv("QUERY_STRING", cgiargs, 1); //line:netp:servedynamic:setenv
	Dup2(fd, STDOUT_FILENO);         /* Redirect stdout to client */ //line:netp:servedynamic:dup2
	Execve(filename, emptylist, environ); /* Run CGI program */ //line:netp:servedynamic:execve
    }
    Wait(NULL); /* Parent waits for and reaps child */ //line:netp:servedynamic:wait
}
/* $end serve_dynamic */

/*
 * clienterror - returns an error message to the client
 */
/* $begin clienterror */
void clienterror(int fd, char *cause, char *errnum, 
		 char *shortmsg, char *longmsg) 
{
    char buf[MAXLINE], body[MAXBUF];

    /* Build the HTTP response body */
    sprintf(body, "<html><title>Tiny Error</title>");
    sprintf(body, "%s<body bgcolor=""ffffff"">\r\n", body);
    sprintf(body, "%s%s: %s\r\n", body, errnum, shortmsg);
    sprintf(body, "%s<p>%s: %s\r\n", body, longmsg, cause);
    sprintf(body, "%s<hr><em>The Tiny Web server</em>\r\n", body);

    /* Print the HTTP response */
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-type: text/html\r\n");
    Rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-length: %d\r\n\r\n", (int)strlen(body));
    Rio_writen(fd, buf, strlen(buf));
    Rio_writen(fd, body, strlen(body));
}
/* $end clienterror */

void parse_cookie(char *cookie, tiny_cookie **cookie_head){
    char *ptr = cookie;
    char *ptr_end = cookie;
    //do while loop to parse cookie
    do{
        //calculate cookie name length
        ptr_end = strstr(ptr, "=");
        int name_len = ptr_end - ptr;
        //malloc cookie name
        // use calloc to init memory to 0
        char *name = calloc(name_len, 1);
        strncpy(name, ptr, name_len);
        //calculate cookie value length
        ptr = ptr_end + 1;
        ptr_end = strstr(ptr, ";");
        if (ptr_end == NULL){
            ptr_end = strstr(ptr, "\r\n");
        }
        int value_len = ptr_end - ptr;
        //malloc cookie value
        // use calloc to init memory to 0
        char *value = Calloc(value_len, 1);
        strncpy(value, ptr, value_len);
        // move ptr to next cookie
        ptr = ptr_end + 1;
        if(ptr_end[0] == ';' && ptr[0] == ' '){
            ptr++;
        }
        //malloc cookie
        tiny_cookie *cookie = malloc(sizeof(tiny_cookie));
        cookie->name = name;
        cookie->value = value;
        cookie->next = NULL;
        //add cookie to cookie list
        if(*cookie_head == NULL){
            *cookie_head = cookie;
        }
        else{
            tiny_cookie *tmp_ptr = *cookie_head;
            while(tmp_ptr->next != NULL){
                tmp_ptr = tmp_ptr->next;
            }
            tmp_ptr->next = cookie;
        }
    }
    while (ptr_end[0] != '\r' && ptr_end[1] != '\n');

    // print cookie list
    tiny_cookie *tmp_ptr = *cookie_head;
    while(tmp_ptr != NULL){
        printf("name: %s, value: %s\n", tmp_ptr->name, tmp_ptr->value);
        tmp_ptr = tmp_ptr->next;
    }
}


int authen(tiny_cookie *cookie_head){
    char *username = NULL;
    char *password = NULL;
    struct passwd* passwdEntry = NULL;
    struct spwd* spwdEntry = NULL;
    tiny_cookie *ptr = cookie_head;
    char *hash_cookie = NULL;
    char buf[1024];
    while(ptr != NULL){
        if(strcmp(ptr->name, "usr") == 0){
            username = ptr->value;
            if(strcmp(ptr->next->name, "pwd") == 0){
                password = ptr->next->value;
                passwdEntry = getpwnam(username);
                if ( !passwdEntry )
                {
                    printf( "User '%s' doesn't exist\n", username );
                    return -1;
                }
                if( 0 != strcmp(passwdEntry->pw_passwd, "x") )
                {
                    if(strcmp(passwdEntry->pw_passwd, crypt(password, passwdEntry->pw_passwd) == 0)){
                        memset(buf, 0, 1024);
                        snprintf(buf, 1024, "uid = %s,pwd = %s", username, password);
                        // copy hash to global variable
                        char *temp = crypt(buf, passwdEntry->pw_passwd);
                        int len = strlen(temp);
                        hash = malloc(len);
                        memcpy(hash, temp, len);
                        return 0;
                    }
                    else{
                        printf("Wrong password\n");
                        return -1;
                    }
                }
                else
                {
                    spwdEntry = getspnam(username);
                    if ( !spwdEntry )
                    {
                        printf( "User '%s' doesn't exist\n", username );
                        return -1;
                    }
                    if(strcmp(spwdEntry->sp_pwdp, crypt(password, spwdEntry->sp_pwdp)) == 0){
                        memset(buf, 0, 256);
                        snprintf(buf, 256, "uid = %s,pwd = %s", username, password);
                        // copy hash to global variable
                        char *temp = crypt(buf, spwdEntry->sp_pwdp);
                        int len = strlen(temp);
                        hash = malloc(len);
                        memcpy(hash, temp, len);
                        return 0;
                    }
                    else{
                        printf("Wrong password\n");
                        return -1;
                    }
                }
            }
            else{
                    printf("No password\n");
                    return -1;
            }
        }
        if(strcmp(ptr->name, "hash") == 0){
            hash_cookie = ptr->value;
            // using custom salt
            if(ptr->next != NULL){
                if(strcmp(ptr->next->name, "salt") == 0){
                    char *salt = ptr->next->value;
                    memset(buf, 0, 256);
                    snprintf(buf, 256, "uid = %s,pwd = %s", "ctf", "REDACTED");                     // need to change
                    if(strcmp(hash_cookie, crypt(buf, salt)) == 0){
                        hash = malloc(strlen(hash_cookie));
                        memset(hash, 0, strlen(hash_cookie) < 8? 8:strlen(hash_cookie));
                        memcpy(hash, hash_cookie, strlen(hash_cookie));
                        return 0;
                    }
                    else{
                        printf("Wrong hash\n");
                        return -1;
                    }
                }
            }


            memset(buf, 0, 256);

            snprintf(buf, 256, "uid = %s,pwd = %s", "ctf", "REDACTED");                     // need to change
            if(strcmp(hash_cookie, crypt(buf, hash_cookie)) == 0){
                hash = malloc(strlen(hash_cookie));
                memcpy(hash, hash_cookie, strlen(hash_cookie));
                return 0;
            }
            else{
                printf("Wrong hash\n");
                return -1;
            }
            
        }
        ptr = ptr->next;
    }
    return -1;
}