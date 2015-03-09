TARGETS=hw4

hw3: hw4.c
	gcc -g -o hw4 hw4.c

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

