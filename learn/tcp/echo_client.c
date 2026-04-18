#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT        9000
#define BUFFER_SIZE 1024

int main() {
    int sock_fd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    int bytes_read;

 sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) { perror("socket"); exit(1); }

 memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port   = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) == -1) {
        perror("inet_pton"); exit(1);
    }
  if (connect(sock_fd, (struct sockaddr*)&server_addr,
                sizeof(server_addr)) == -1) {
        perror("connect"); exit(1);
    }

    printf("[+] Connected to server on port %d\n", PORT);
     while (1) {
        printf("Enter message (or 'quit'): ");
        fgets(buffer, BUFFER_SIZE, stdin);

        if (strncmp(buffer, "quit", 4) == 0) break;

        write(sock_fd, buffer, strlen(buffer));

        bytes_read = read(sock_fd, buffer, BUFFER_SIZE);
        buffer[bytes_read] = '\0';
        printf("[<] Echo: %s", buffer);
    }

    close(sock_fd);
    printf("[*] Disconnected\n");
    return 0;
}