#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
  int i, x, y;
  if (!argv[1] || !argv[2])
  {
    printf("%s <string> <pass>n", argv[0]);
    return 0;
  }
  x = strlen(argv[1]);
  y = strlen(argv[2]);
  for (i = 0; i < x; ++i)
    argv[1][i] ^= argv[2][(i%y)];
    
  printf("pkt%s",argv[1]);
  return 0;
}
