#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main()
{
    printf("%ld\n", sizeof(struct sockaddr_in));
}
