gcc -Wall -O2 -DETCDIR=\"/etc\"  -DHAVE_GETOPT_H=1 -DHAVE_MATH_H=1   -c xmlwebalizer.c
gcc -Wall -O2 -DETCDIR=\"/etc\"  -DHAVE_GETOPT_H=1 -DHAVE_MATH_H=1   -c hashtab.c
gcc -Wall -O2 -DETCDIR=\"/etc\"  -DHAVE_GETOPT_H=1 -DHAVE_MATH_H=1   -c linklist.c
gcc -Wall -O2 -DETCDIR=\"/etc\"  -DHAVE_GETOPT_H=1 -DHAVE_MATH_H=1   -c preserve.c
gcc -Wall -O2 -DETCDIR=\"/etc\"  -DHAVE_GETOPT_H=1 -DHAVE_MATH_H=1   -c dns_resolv.c
gcc -Wall -O2 -DETCDIR=\"/etc\"  -DHAVE_GETOPT_H=1 -DHAVE_MATH_H=1   -c parser.c
gcc -Wall -O2 -DETCDIR=\"/etc\"  -DHAVE_GETOPT_H=1 -DHAVE_MATH_H=1   -c xmloutput.c
gcc  -o xmlwebalizer xmlwebalizer.o hashtab.o linklist.o preserve.o parser.o xmloutput.o dns_resolv.o -lz -lm 
rm -f webazolver
ln -s webalizer webazolver

