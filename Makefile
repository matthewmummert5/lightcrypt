OBJDIR=object
SRCDIR=source
INCDIR=include

CC = gcc
CFLAGS = -c -Wall


INCLUDES = -I include/ -I nacl/include/amd64

OBJECTS =	$(OBJDIR)/main.o	\
		$(OBJDIR)/lock.o	\
		$(OBJDIR)/tweetnacl.o	\
		$(OBJDIR)/randombytes.o



all: project

project: main.o lock.o tweetnacl.o randombytes.o
		$(CC) $(INCLUDES) $(OBJECTS) -o lightcrypt

main.o: $(SRCDIR)/main.c
		$(CC) $(INCLUDES) $(CFLAGS) $(SRCDIR)/main.c -o $(OBJDIR)/main.o


lock.o: $(SRCDIR)/lock.c
		$(CC) $(INCLUDES) $(CFLAGS) $(SRCDIR)/lock.c -o $(OBJDIR)/lock.o

tweetnacl.o: $(SRCDIR)/tweetnacl.c
		$(CC) $(INCLUDES) $(CFLAGS) $(SRCDIR)/tweetnacl.c -o $(OBJDIR)/tweetnacl.o

randombytes.o: $(SRCDIR)/randombytes.c
		$(CC) $(INCLUDES) $(CFLAGS) $(SRCDIR)/randombytes.c -o $(OBJDIR)/randombytes.o
		
clean:

		rm -rf object/*.o lightcrypt


