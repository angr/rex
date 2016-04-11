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

size_t receive_n( int fd, unsigned char *dst, size_t n_bytes )
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

void do_write_what_where() {
    // I use a struct for the stack to guarantee layout
    struct stack_func_1 stack;
    const char *message = "This should print out 4 A's\n";
    int foo = 0x5a5a5a5a;
    stack.where = &foo;
    stack.what = 0x41414141;
    receive_until(0, stack.buf, '\n', 0x28);
    *(stack.where) = stack.what;
    send_all(1, message, strlen(message));
    send_all(1, (char *)&foo, 4);
    send_all(1, "\n", 1);
}

void some_other_func() {
    const char *message = "It could even be extended to check some cfi and then we could see if an exploit is still possible\n";
    send_all(1, message, strlen(message));
    do_write_what_where();
}

int main() {
  char buf[0x100] = "Hello this is a test program with a write what where\n";
  send_all(1, buf, 67);
  some_other_func();

  return 0;
}



