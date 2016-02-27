CFLAGS=-lgcc -lpcap
BINDIR=/usr/local/bin

c: ethernet.h helpers.c helpers.h ip4.h linked_list.c linked_list.h linked_list_node.h PTNM.c PTNM.h sip.h tcp.h udp.h
	gcc -o PTNM helpers.c linked_list.c PTNM.c  ${CFLAGS} 
	sudo chown root PTNM
	sudo chmod u+s PTNM

cpp: ethernet.h helpers.c helpers.h ip4.h linked_list.c linked_list.h linked_list_node.h PTNM.cpp PTNM.h sip.h tcp.h udp.h
	g++ -o PTNM -fpermissive helpers.c linked_list.c PTNM.cpp ${CFLAGS}
	sudo chown root PTNM
	sudo chmod u+s PTNM

clean:
	rm -f PTNM
install: PTNM
	sudo rsync -aH PTNM ${BINDIR}/  
uninstall: 
	sudo rm -f ${BINDIR}/PTNM
