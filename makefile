all: myELF

myELF: myELF.c
	gcc -m32 -g -Wall myELF.c -o myELF

clean:
	rm -f myELF