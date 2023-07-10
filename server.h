#ifndef SERVER_H
#define SERVER_H

#define __STDC_WANT_LIB_EXT1__ 1
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // fork()
#include <string.h>
#include <signal.h> // sigaction(), sigemptyset()
#include <sys/wait.h> // wait()
#include <sys/socket.h>
#include <netdb.h> // struct addrinfo
#include <arpa/inet.h>  // inet_ntoa()
#include <sys/mman.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>

#define CLIENTS_MEM_SZ 1024L   /* data buffer to store clients_t struct and struct client linked list */
#define MESSAGES_MEM_SZ 1024L  /* data buffer to store struct message linked list */
#define MESSAGES_BUF_SZ 128L   /* text buffer located at the bottom of MESSAGES_MEM */
#define MESSAGES_BUF_MEM (MESSAGES_MEM_SZ - MESSAGES_BUF_SZ)

#define PORT_STR "27007"
#define WELCOME_MSG "Server-> Welcome to SOCKETLAND."

typedef enum { INFO, MESSAGE , MSG_TYPE_MAX } msg_type_t;

struct client {
	pid_t pid;
	int id;
	int sockfd;
	int pad;
	time_t time_join;
	struct client *next;
}; // sz 32

struct message {
	char *msg;
	size_t lenght;
	int sender_id;
	int echos;
	struct message *next;
}; // sz 32

typedef struct {
	int cnt;
	int pad;
	void *message_mem;
	time_t time_up;
	struct client *chead;
	struct message *mhead;
} clients_t; // sz 40


#define GENERATE_ENUM(ENUM) cmd_##ENUM,
#define GENERATE_STRING(STRING) #STRING,

#define MIN(a,b) ((a<b) ? a : b)

#define MAX_CLIENTS MIN(((CLIENTS_MEM_SZ-sizeof(clients_t)) / sizeof(struct client) - 1) , \
					 ((MESSAGES_MEM_SZ-MESSAGES_BUF_SZ) / sizeof(struct message) - 1))


int create_socket(void);
void set_signals(void);
void console(void);
int get_free_id(struct client *chead);
int get_pid_by_id(clients_t *clients, int id);
void print_clients(clients_t *clients);
int add_client(clients_t *clients, int sockfd, pid_t pid);
int check_id(clients_t *clients, int id);
void remove_client(clients_t *clients, int id);
static void sigchld_handler(int signal);
void socket_disconnected(int signal);
int kick_client(clients_t *clients, int id);
void terminate_childrens(void);
void exit_program(int signal);
void* create_shared_memory(size_t size);
void unmap_mem(void);
size_t getLine(char *buf, int buf_sz);
void *thread_listen(void *data);
void print_commands_help(void);
static void sigusr1_handler(int signal, siginfo_t *info, void *ucontext);
static void dummy_handler(int s);
int send_echo(clients_t *clients, msg_type_t concept, const char *buf, int sender_id);
int send_message(clients_t *clients, msg_type_t concept, char *buf, int sender_id, int dest_id);
void pop_msg(clients_t *clients, int sender_id);
struct message *push_msg(clients_t *clients, char *buf, size_t len, int sender_id, int echos);
struct message *get_message(clients_t *clients, int id);
char *get_ip_str(const struct sockaddr *sa, char *s, socklen_t maxlen);


#endif // SERVER_H
