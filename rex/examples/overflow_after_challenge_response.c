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

unsigned int rand_range(unsigned int min, unsigned int max) {
  unsigned int lrand;
  random(&lrand, 4, NULL);
  if (max-min+1 == 0) {
    return lrand;
  }
  return (lrand % (max-min+1)) + min;
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

void int_to_str(int num, int base, char *dst) {
  char const digit[] = "0123456789abcdefghijkl";
  char* p = dst;
  if(num < 0){
      *p++ = '-';
      num *= -1;
  }
  int shifter = num;
  do{ //Move to where representation ends
      ++p;
      shifter = shifter/base;
  } while (shifter);
  *p = '\x00';
  do{ //Move back, inserting digits as u go
      *--p = digit[num%base];
      num = num/base;
  }while(num);
}

// STRTOL
#define IS_SPACE(c) ((c == ' ') || (c == '\t') || (c == '\f') || (c == '\n') || (c == '\v'))
#define IS_NUM(c) ((c >= '0') && (c <= '9'))
#define IS_ALPHA(c) (((c >= 'A') && (c <= 'Z')) || ((c >= 'a') && (c <= 'z')))
#define IS_UPPER(c) ((c >= 'A') && (c <= 'Z'))

long int strtol(const char *nptr, char **endptr, int base)
{
    int neg = 0, val = 0, consumed = 0, n, a;
    const char *p = nptr;

    /* Check validity of base */
    if (base == 1 || base > 36 || base < 0)
        goto done;

    /* Skip white space */
    while (1)
    {
        if (IS_SPACE(*p))
            ++p;
        else
            break;
    }

    /* Check sign symbol */
    if (*p == '-')
    {
        neg = 1;
        ++p;
    }
    if (*p == '+')
        ++p;

    /* Handle the base & its syntax */
    switch (base)
    {
        case 0:
            if (*p == '0')
            {
                if (p[1] == 'x' || p[1] == 'X')
                {
                    p += 2;
                    base = 16;
                }
                else
                {
                    ++p;
                    base = 8;
                }
            }
            else
                base = 10;
            break;
        case 16:
            if (*p == '0' && (p[1] == 'x' || p[1] == 'X'))
            {
                p += 2;
                base = 16;
            }
            break;
    }

    /* Convert the rest of the string into int */
    while ((n = IS_NUM(*p)) || (a = IS_ALPHA(*p)))
    {
        if (n)
            n = *p - '0';
        else if (a)
        {
            if (IS_UPPER(*p))
                n = *p - 'A';
            else
                n = *p - 'a';
            // "... In bases above 10, the letter 'A' in either upper  or  lower case represents 10,
            //      'B' represents 11, and so forth, with 'Z' representing 35. ..."
            n += 10;
        }

        // "... stopping at the first character which is not a valid digit in the given base. ..."
        if (n >= base)
            break;

        val *= base;
        val += n;
        ++consumed;
        ++p;
    }

    if (neg)
        val = -val;

done:
    if (endptr)
        *endptr = (char *)(consumed > 0 ? p : nptr);

    return val;

}

long unsigned int strtoul(const char *nptr, char **endptr, int base)
{
    return (long unsigned int)strtol(nptr, endptr, base);
}
// STRTOL

size_t receive_n( int fd, void *dst_a, size_t n_bytes )
{
  char *dst = (char *)dst_a;
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

int play_game() {
    int rand = 0;
    int *flag = (int*)0x4347c000;
    for (int i = 0; i < 32; i++) {
        rand += flag[i];
    }
    // char buf[0x20];
    int ans;

    send_all(1, &rand, 4);
    // TODO change this to rand*2-0x1234
    // TODO change this to atoi/strtol
    receive_n(0, &ans, 4);

    return ans == rand;
}

int main() {
  char buf[0x100] = "Hello this is a test program where you must first solve a challenge response before overflow\n";
  send_all(1, buf, strlen(buf));

  if (play_game()) {
    send_all(1, "give me a message: ", strlen("give me a message: "));
    receive_until(0, buf, '\n', 0x200);
  } else {
    send_all(1, "Nope!\n", strlen("Nope!\n"));
  }

  return 0;
}


