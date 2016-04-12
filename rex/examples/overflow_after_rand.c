#include <libcgc.h>

typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;

struct stack_func_1 {
  char buf[0x20];
  int *where;
  int what;
};

size_t receive_until(int fd, char *dst, char delim, size_t max )
{
    size_t len = 0;
    size_t rx = 0;
    char c = 0;

    while( len < max ) {
        dst[len] = 0x00;

        if ( receive( fd, &c, 1, &rx ) != 0 ) {
            len = 0;
            goto end;
        }

        if ( c == delim ) {
            goto end;
        }

        dst[len] = c;
        len++;
    }
end:
    return len;
}

void *memcpy(void *dst, const void *src, size_t n) {
   char *d = (char*)dst;
   const char *s = (const char *)src;
   while (n--) {*d++ = *s++;}
   return dst;
}

int strlen(const char *s) {
    int len = 0;
    while (s[len]) {
        len++;
    }
    return len;
}

size_t receive_n( int fd, char *dst, size_t n_bytes )
{
  size_t len = 0;
  size_t rx = 0;
  while(len < n_bytes) {
    if (receive(fd, dst + len, n_bytes - len, &rx) != 0) {
      len = 0;
      break;
    }
    len += rx;
  }

  return len;
}

int send_all(int fd, const void *msg, size_t n_bytes)
{
  size_t len = 0;
  size_t tx = 0;
  while(len < n_bytes) {
    if (transmit(fd, (char *)msg + len, n_bytes - len, &tx) != 0) {
      return 1;
    }
    len += tx;
  }
  return 0;
}

void do_win() {
    const char *message = "Here's your overflow!!!\n";
    char name[0x20];
    send_all(1, message, strlen(message));
    receive_until(0, name, '\n', 0x40);
}

void play_game() {
    char r;
    char guess[2];
    if(random(&r, 1, NULL)) {
        return;
    }
    const char *message = "Guess: ";
    send_all(1, message, strlen(message));
    receive_until(0, guess, '\n', 2);
    if (r == guess[0]) {
        do_win();
    }
}

int main() {
  char buf[0x100] = "Hello this is a test program where you must first guess a 1 byte random number then you can overflow\n";
  char resp[2];
  send_all(1, buf, strlen(buf));
  int loop = 1;
  while (loop) {
    play_game();
    send_all(1, "continue? ", strlen("continue? "));
    receive_until(0, resp, '\n', 2);
    if (resp[0] == 'y' || resp[0] == 'Y') {
        loop = 1;
    } else {
        loop = 0;
    }
  }

  return 0;
}


