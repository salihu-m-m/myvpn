#include <stdio.h>    
#include <stdlib.h>   
#include <string.h>   
#include <unistd.h>   
#include <arpa/inet.h> 
#include <sys/socket.h>

#define PORT        9000
#define BUFFER_SIZE 1024

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];
    int bytes_read;
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
if(server_fd == -1){perror("socket"); exit(1);}

 int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
   memset(&address, 0, sizeof(address));
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port        = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) == -1) {
        perror("bind"); exit(1);
    }
   if (listen(server_fd, 1) == -1) {
        perror("listen"); exit(1);
    }

    printf("[*] Server listening on port %d\n", PORT);
     client_fd = accept(server_fd, (struct sockaddr*)&address, &addrlen);
    if (client_fd == -1) { perror("accept"); exit(1); }

    printf("[+] Client connected\n");
      while ((bytes_read = read(client_fd, buffer, BUFFER_SIZE)) > 0) {
        buffer[bytes_read] = '\0';
        printf("[>] Received: %s", buffer);
        write(client_fd, buffer, bytes_read);
    }

    printf("[-] Client disconnected\n");
     close(client_fd);
    close(server_fd);
    return 0;


}
