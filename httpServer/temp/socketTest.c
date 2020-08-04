#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(){

  int sock;
  struct sockaddr_in serv_addr;
  char message[10000] = {1, 2};
  sock = socket(PF_INET, SOCK_STREAM, 0);
  if(sock == -1)
    printf("Socket error\n");
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  serv_addr.sin_port = htons(5432);
  if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    printf("Connect Error\n");

  if(send(sock, message, sizeof(message)-1, 0 < 0))
    printf("Send error\n");

  if(read(sock, message, sizeof(message)-1) == -1)
    printf("Read error\n");
  printf("Server says: %s\n", message);
  close(sock);
  return 0;

}
