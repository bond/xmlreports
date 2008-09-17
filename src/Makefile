# CFLAGS = -Wall -O2
CFLAGS = -Wall -g
LDFLAGS = -lz -lm
CC = cc
OBJS = xmlwebalizer.o hashtab.o linklist.o preserve.o parser.o xmloutput.o dns_resolv.o
OBJFLAGS = -DETCDIR=\"/etc\"  -DHAVE_GETOPT_H=1 -DHAVE_MATH_H=1
all: xmlwebalizer

%.o: %.c
	$(CC) -c $^ $(CFLAGS) $(OBJFLAGS)

xmlwebalizer: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

testrun: xmlwebalizer
	cat ./test/*.log |./xmlwebalizer -p -n `hostname` -C 0 -o ./test/

clean:
	rm *.o *~ xmlwebalizer test/*.xml test/webalizer.*
