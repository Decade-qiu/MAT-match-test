#include<stdio.h>
#include <syslog.h>

int main(){
    openlog("myapp", LOG_PID, LOG_USER);
    syslog(LOG_INFO, "Hello, syslog!");
    closelog();
    printf("okkkkkkkkkk!\n");
    return 0;
}