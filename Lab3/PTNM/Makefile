CFLAGS=-lpcap /usr/lib64/libc_nonshared.a
BINDIR=/usr/local/bin

c: ethernet.h helpers.c helpers.h ip4.h linked_list.c linked_list.h linked_list_node.h PTNM.c PTNM.h sip.h tcp.h udp.h
	gcc -o PTNM ${CFLAGS} helpers.c linked_list.c PTNM.c 
	sudo chown root PTNM
	sudo chmod u+s PTNM

cpp: ethernet.h helpers.c helpers.h ip4.h linked_list.c linked_list.h linked_list_node.h PTNM.cpp PTNM.h sip.h tcp.h udp.h
	g++ -o PTNM -fpermissive ${CFLAGS} helpers.c linked_list.c PTNM.cpp
	sudo chown root PTNM
	sudo chmod u+s PTNM

clean:
	rm -f PTNM
install: PTNM
	sudo rsync -aH PTNM ${BINDIR}/  
uninstall: 
	sudo rm -f ${BINDIR}/PTNM
