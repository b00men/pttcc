server.c: NetServer.c NetServer.h NetHost.h NetHost.c VSNPServerMain.c
	gcc -o VSNPServer NetHost.c NetServer.c VSNPServerMain.c

server.cpp: NetServer.c NetServer.h NetHost.h NetHost.c VSNPServerMain.cpp
	g++ -Wno-pointer-arith -Wno-write-strings -o VSNPServer NetHost.c NetServer.c VSNPServerMain.cpp

client.c: NetClient.c NetClient.h NetHost.h NetHost.c VSNPClientMain.c
	gcc  -o VSNPClient NetHost.c NetClient.c VSNPClientMain.c

client.cpp: NetClient.c NetClient.h NetHost.h NetHost.c VSNPClientMain.cpp
	g++ -Wno-pointer-arith -Wno-write-strings -o VSNPClient NetHost.c NetClient.c VSNPClientMain.cpp

clean:
	rm -rf ./VSNPServer ./VSNPClient
