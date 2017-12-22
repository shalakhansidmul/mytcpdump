go: mydump.c
	gcc -o mydump mydump.c -lpcap
clean:
	rm mydump
