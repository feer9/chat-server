#ifndef SERVER_H
#define SERVER_H

#define __STDC_WANT_LIB_EXT1__ 1
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
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
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CLIENTS_MEM_SZ 1024L   /* data buffer to store sdata_t struct and struct client linked list */
#define MESSAGES_MEM_SZ 1024L  /* data buffer to store struct message linked list */
#define MESSAGES_BUF_SZ 128L   /* text buffer located at the bottom of MESSAGES_MEM */
#define MESSAGES_BUF_MEM (MESSAGES_MEM_SZ - MESSAGES_BUF_SZ)

#define PORT_STR "27007"
#define WELCOME_MSG "Server-> Welcome to SOCKETLAND."

typedef enum { INFO, MESSAGE , MSG_TYPE_MAX } msg_type_t;

struct process_data {
	pid_t pid;        // Process ID
	int cid;          // Client ID
	int sockfd;       // Socket File Descriptor
	__attribute__((unused)) int _padding[1];
	time_t time_join;
	SSL_CTX *ssl_ctx;
	SSL     *ssl;
};

struct client {
	struct process_data *pdata;
	struct client *next;
};

struct message {
	char *msg;
	size_t lenght;
	int sender_id;
	atomic_int echos;
	struct message *next;
}; // sz 32

// Server shared data structure
typedef struct {
	int clients_cnt;
	__attribute__((unused)) int _padding[1];
	void *message_mem;     // memory start location for i/o operations
	time_t time_up;
	struct client  *chead; //  clients linked list head
	struct message *mhead; // messages linked list head
} sdata_t; // sz 40


#define GENERATE_ENUM(ENUM) cmd_##ENUM,
#define GENERATE_STRING(STRING) #STRING,

// Here I define the list of available commands, which then generates
// an enum of the form cmd_<commandname> and a string "<commandname>"
#define COMMAND_LIST(CMD)	\
	CMD(quit)				\
	CMD(kick)				\
	CMD(say)				\
	CMD(clients)			\
	CMD(uptime)				\
	CMD(stats)				\
	CMD(status)				\
	CMD(help)				\
	CMD(info)

typedef enum {
	COMMAND_LIST(GENERATE_ENUM)
	cmd_CONTINUE,
	cmd_MAX
} commands_e;

typedef struct {
	commands_e id;
	const char *str;
	const char *arg;
} command_t;



#define MIN(a,b) ((a<b) ? a : b)

#define MAX_CLIENTS MIN(((CLIENTS_MEM_SZ-sizeof(sdata_t)) / sizeof(struct client) - 1) , \
					 ((MESSAGES_MEM_SZ-MESSAGES_BUF_SZ) / sizeof(struct message) - 1))

#if 1
#define dbg_print(...) do{fprintf(stderr, __VA_ARGS__); fflush(stdout);}while(0)
#define dbg_print_safe(s) write(2, s, strlen(s))
#else
#define dbg_print(...) while(0) continue
#define dbg_print_safe(s) while(0) continue
#endif

void set_signals(sdata_t *sdata);
command_t* readCmd(sdata_t *sdata);
void handle_readerr(sdata_t *sdata);
void console(sdata_t *sdata);
int cmd_KickUser(sdata_t *sdata, int user_id);
int cmd_KickUser_s(sdata_t *sdata, const char *id_str);
void print_clients(sdata_t *sdata);
void print_uptime(sdata_t *sdata);
void print_commands_help(void);
size_t getLine(char *buf, int buf_sz);
void *thread_listen(void *data);
int create_socket(void);
char *get_ip_str(const struct sockaddr *sa, char *s, socklen_t maxlen);
int kick_client(sdata_t *sdata, int id);
int get_free_id(struct client *chead);
pid_t get_pid_by_id(sdata_t *sdata, int id);
int get_id_by_pid(sdata_t *sdata, int id);
int check_id(sdata_t *sdata, int id);
int add_client(sdata_t *sdata, struct process_data*);
void remove_client(sdata_t *sdata, int id);
struct message *get_message(sdata_t *sdata, int id);
struct message *push_msg(sdata_t *sdata, char *buf, size_t len, int sender_id, int echos);
void pop_msg(sdata_t *sdata, int sender_id);
int send_message(sdata_t *sdata, msg_type_t concept, char *buf, int sender_id, int dest_id);
int send_echo(sdata_t *sdata, msg_type_t concept, const char *buf, int sender_id);
static void sigusr1_handler(int signal, siginfo_t *info, void *ucontext);
static void dummy_handler(int s);
static void sigchld_handler(int signal);
static void sigpipe_handler(int signal);
void* create_shared_memory(size_t size);
void unmap_mem(int status, void* data);
void close_connections(int status, void* data);
void report_socket_down(sdata_t *sdata);
void wait_for_child(sdata_t *sdata);
void terminate_children(int status, void* data);
void exit_program(int signal);
void sleep_ms(int ms);

void initialize_openssl(void);
void cleanup_openssl(void);
SSL_CTX *create_ssl_context(void);
void configure_ssl_context(SSL_CTX *ctx);


#endif // SERVER_H
