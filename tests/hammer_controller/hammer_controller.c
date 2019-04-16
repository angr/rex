#include <stdio.h>
#include <string.h>
#include <unistd.h>

char password[21]    = {0} ;
char secret[32]      = {0} ;

int main(int argc, char *argv[])
{
    struct avenger
    {
        char buffer[64];
        int is_worthy;
    } avenger;


    avenger.is_worthy = 0;

    if(argc != 3)
    {
        return 1;
    }

    puts("Asgard's secrets are safe!");

    strncpy(secret, argv[1], 32);
    strncpy(password, argv[2], 21);

    puts("Try lift the hammer, go ahead!");

    // let them attempt
    read(0, avenger.buffer, 1024);
    // Assess their worth
    if (!strncmp(avenger.buffer, password, strlen(password)))
    {
        avenger.is_worthy = 42;
    }

    if (avenger.is_worthy)
    {
        printf("Welcome Vision, Bifröst awaits you! \nHere's your access token: %s\n", secret);
    }
    // You're all not worthy!
    else
    {
        puts("Come on Toni.");
    }
    return 0;
}
