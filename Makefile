all: swifi test_swifi kdisasm 

swifi: swifi.c swifi.h
	gcc swifi.c -o swifi

test_swifi: test_swifi.c swifi.h
	gcc test_swifi.c -o test_swifi

kdisasm: kdisasm.c
	gcc kdisasm.c -o kdisasm

clean: 
	rm -f *.o swifi test_swifi kdisasm
