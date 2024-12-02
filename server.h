#ifndef SERVER_H
#define SERVER_H

#define __STDC_WANT_LIB_EXT1__ 1
#define _XOPEN_SOURCE 700
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
#include <stdatomic.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

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
	atomic_int echos;
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

#if 0
#define dbg_print(...) do{fprintf(stderr, __VA_ARGS__); fflush(stdout);}while(0)
#define dbg_print_safe(s) write(2, s, strlen(s))
#else
#define dbg_print(...) while(0) continue
#define dbg_print_safe(s) while(0) continue
#endif

int create_socket(void);
void set_signals(void);
void console(void);
int get_free_id(struct client *chead);
pid_t get_pid_by_id(clients_t *clients, int id);
int get_id_by_pid(clients_t *clients, int id);
void print_clients(clients_t *clients);
void print_commands_help(void);
void print_uptime(void);
int add_client(clients_t *clients, int sockfd, pid_t pid);
int check_id(clients_t *clients, int id);
void remove_client(clients_t *clients, int id);
int kick_client(clients_t *clients, int id);
int cmd_KickUser(int user_id);
int cmd_KickUser_s(const char *id_str);
void socket_disconnected(int signal);
void close_connections(void);
void terminate_childrens(void);
void exit_program(int signal);
void* create_shared_memory(size_t size);
void unmap_mem(void);
size_t getLine(char *buf, int buf_sz);
void *thread_listen(void *data);
static void sigusr1_handler(int signal, siginfo_t *info, void *ucontext);
static void sigchld_handler(int signal);
static void dummy_handler(int s);
int send_echo(clients_t *clients, msg_type_t concept, const char *buf, int sender_id);
int send_message(clients_t *clients, msg_type_t concept, char *buf, int sender_id, int dest_id);
void pop_msg(clients_t *clients, int sender_id);
struct message *push_msg(clients_t *clients, char *buf, size_t len, int sender_id, int echos);
struct message *get_message(clients_t *clients, int id);
char *get_ip_str(const struct sockaddr *sa, char *s, socklen_t maxlen);
void sleep_ms(int ms);

void initialize_openssl(void);
void cleanup_openssl(void);
SSL_CTX *create_ssl_context(void);
void configure_ssl_context(SSL_CTX *ctx);


#endif // SERVER_H
