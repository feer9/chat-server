#include "server.h"

static char port[8] = PORT_STR;

// each process data:
static struct process_data pdata = {
		.pid = -1,
		.cid = -1,
		.sockfd = -1,
		.ssl_ctx = NULL,
		.ssl = NULL
};
static volatile sig_atomic_t sigchld_received = 0;
static volatile sig_atomic_t sigpipe_received = 0;

int main(int argc, char *argv[])
{
	static sdata_t *sdata;
	if(argc == 2 && atoi(argv[1]) > 0)
		strncpy(port, argv[1], 7);

	if((sdata = (sdata_t*) create_shared_memory(CLIENTS_MEM_SZ) ) == MAP_FAILED)
		exit(1);
	if((sdata->message_mem = create_shared_memory(MESSAGES_MEM_SZ)) == MAP_FAILED)
		exit(1);
	sdata->clients_cnt = 0;
	sdata->chead = NULL;
	sdata->mhead = NULL;
	sdata->time_up = time(NULL);

	pdata.pid = getpid();
	pdata.cid = 0;  // server id = 0

	set_signals(sdata);

	pthread_t thread_id;
	pthread_create(&thread_id, NULL, thread_listen, sdata);
	pthread_detach(thread_id);

	console(sdata);

	exit(0);
}

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

static const char *commands_string[] = {
    COMMAND_LIST(GENERATE_STRING)
	"", /* cmd_CONTINUE */
};

typedef struct {
	commands_e id;
	const char *str;
	const char *arg;
} command_t;

static int compare_cmd(const void *a, const void *b)
{
	return strcmp(((command_t *) a)->str, ((command_t *) b)->str);
}

static void init_commands(command_t *commands)
{
	for(commands_e i=0; i<cmd_MAX; i++)
	{
		commands[i].id = i;
		commands[i].str = commands_string[i];
		commands[i].arg = 0;
	}
	qsort(commands, cmd_MAX, sizeof *commands, compare_cmd);
}

static command_t commands[cmd_MAX];

static command_t* readCmd(sdata_t *sdata)
{
	static char buf[64] = "";
	static command_t input_cmd;
	int cmd_len=0;
	char c;

	size_t readsz = getLine(buf, sizeof buf);
	if(readsz == 0) {
		handle_readerr(sdata);
		input_cmd.id = cmd_CONTINUE;
		return &input_cmd;
	}
	// split command from argument
	while ( cmd_len < (int) sizeof buf &&
	        (c = buf[cmd_len]) != '\0' && !isspace(c) ) {
		cmd_len++;
	}
	buf[cmd_len] = '\0';

	// get command ID
	input_cmd.str = buf;
	input_cmd.arg = NULL;
	command_t *cmd_ptr = bsearch(&input_cmd, commands, cmd_MAX, 
	                             sizeof *commands, compare_cmd);

	if(cmd_ptr) { // command found
		cmd_ptr->arg = buf + cmd_len + 1;
		while(cmd_ptr->arg - buf < (int) sizeof buf && isspace(*cmd_ptr->arg))
			cmd_ptr->arg++;
	}
	else { // invalid command
		input_cmd.id = cmd_MAX;
		cmd_ptr = &input_cmd;
	}

	return cmd_ptr;
}

void handle_readerr(sdata_t *sdata)
{
	if(errno == EINTR) {
		if(sigchld_received) {
			dbg_print("received sigchld in getLine()\n");
			sigchld_received--;
			wait_for_child(sdata);
			return;
		}
		if(sigpipe_received) {
			dbg_print("received sigpipe in getLine()\n");
			sigpipe_received = 0;
			report_socket_down(sdata);
			exit(1);
		}
	}
	exit(0);
}

void console(sdata_t *sdata)
{
	init_commands(commands);

	while(1)
	{
		command_t *cmd = readCmd(sdata);

		switch(cmd->id)
		{
		case cmd_quit:
		    goto quit;

		case cmd_kick:
			cmd_KickUser_s(sdata, cmd->arg);
		    break;

		case cmd_say:
			if(!isgraph(cmd->arg[0])) {
				fputs("Usage: say [msg]\n", stderr);
			}
			else {
				send_echo(sdata, MESSAGE, cmd->arg, 0);
			}
		    break;

		case cmd_clients:
		    print_clients(sdata);
		    break;

		case cmd_uptime:
			print_uptime(sdata);
			break;

		case cmd_stats:
		case cmd_status:
			print_uptime(sdata);
			print_clients(sdata);
			break;

		case cmd_help:
			print_commands_help();
			break;

		case cmd_info:
			printf("Server is running on port %s\n", port);
			printf("Server PID is %d\n", getpid());
			printf("Max allowed clients are: %ld\n", MAX_CLIENTS);
			break;

		case cmd_CONTINUE:
			continue;

		case cmd_MAX:
		    if(cmd->str && *cmd->str)
				printf("Unknown command \"%s\". "
				       "Type \"help\" to view a full command list.\n",
				       cmd->str);
		    break;
		}
	}

    quit:
	send_echo(sdata, INFO, "Server is shutting down...", 0);
}

int cmd_KickUser(sdata_t *sdata, int user_id)
{
	if(check_id(sdata, user_id) != 0) {
		fputs("Invalid cid.\n", stderr);
		return -2;
	}
	else if(send_message(sdata, INFO, "You have been kicked.", 0, user_id) == 0
			&& kick_client(sdata, user_id) == 0) {
		puts("Client kicked.");
		return 0;
	}
	else {
		fprintf(stderr, "Couldn't kick client %d\n", user_id);
		return -3;
	}
}

int cmd_KickUser_s(sdata_t *sdata, const char *id_str)
{
	int user_id = atoi(id_str); // TODO: replace with strtol()

	if(!isdigit(id_str[0])) {
		fputs("Usage: kick [cid]\n", stderr);
		return -1;
	}
	else return cmd_KickUser(sdata, user_id);
}

void *thread_listen(void *data) // TODO: split into functions
{
	sdata_t *sdata = data;
	int clientfd=-1;
	char *buf = ((char*)sdata->message_mem) + MESSAGES_BUF_MEM;
	ssize_t nbytes;
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGCHLD);
	if(pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
		perror("pthread_sigmask");
		exit(1);
	}

	int sockfd = create_socket();

	while(1)
	{
		struct sockaddr_in6 client_addr;
		socklen_t sin_size = sizeof client_addr;
		char addr_str[INET6_ADDRSTRLEN] = "";

		clientfd = accept(sockfd, (struct sockaddr*) &client_addr, &sin_size);
		if(clientfd == -1) {
			perror("accept");
			exit(1);
		}

		get_ip_str((struct sockaddr*) &client_addr, addr_str, sizeof addr_str);
		printf("Accepted connection from \"%s:%s\"\n", addr_str, port);

		pid_t pid = fork();
		if(pid == 0) // child
		{
			if(pthread_sigmask(SIG_UNBLOCK, &set, NULL) != 0) {
				perror("pthread_sigmask");
				exit(1);
			}

			close(sockfd);     // close parent's socket
			// TODO: debería cerrar el ssl_ctx del padre acá?

			// set client data to its own process global structure
			pdata.sockfd = clientfd;
			pdata.pid = getpid();
			pdata.time_join = time(NULL);

			pdata.ssl = SSL_new(pdata.ssl_ctx);
			SSL_set_fd(pdata.ssl, clientfd);

			if (SSL_accept(pdata.ssl) <= 0) {
				ERR_print_errors_fp(stderr);
				exit(1);
			}
			else {
				printf("SSL connection established.\n");
			}

			int cid = add_client(sdata, &pdata);
			if(cid == -1)
			{
				fputs("Max clients reached. Can't add more.\n", stderr);
				strcpy(buf, "Server is full.");
				if (SSL_write(pdata.ssl, buf, (int) strlen(buf)+1) == -1)
					perror("SSL_write");
				exit(1);
			}
			pdata.cid = cid; // set client ID to its process global structure

			printf("Client %d connected.\n", cid);

			strcpy(buf, WELCOME_MSG);
			sprintf(&buf[sizeof(WELCOME_MSG)-1], " Your id is: %d", cid);
			if (SSL_write(pdata.ssl, buf, (int) strlen(buf)+1) == -1) {
				perror("SSL_write");
				exit(1);
			}

			sprintf(buf, "Client %d connected from \"%s\".", cid, addr_str);
			send_echo(sdata, INFO, buf, cid);

			for(;;)
			{
				nbytes = SSL_read(pdata.ssl, buf, MESSAGES_BUF_SZ);
				if(nbytes <= 0) {
					int e = SSL_get_error(pdata.ssl, nbytes);
					if(e == SSL_ERROR_SYSCALL) {
						if(sigpipe_received){
							sigpipe_received = 0;
							dbg_print("received sigpipe from client %d.\n", cid);
							break;
						}
						continue;
					}
					else if(e == SSL_ERROR_ZERO_RETURN){
						dbg_print("SSL_read return 0\n");
						SSL_shutdown(pdata.ssl);
						break;
					}
					else {
						perror("SSL_read"); /* ERR_print_errors_fp(stderr); */
						break;
					}
				}
				printf("Client %d-> %s\n", cid, buf);

				send_echo(sdata, MESSAGE, buf, cid);
			}

			close(clientfd);
			report_socket_down(sdata);
			exit(0);
		}
		else if(pid > 0) // parent
		{
			close(clientfd);
		}
		else
		{
			perror("fork"); // print error and continue
		}
	} // while(1)
}

int create_socket(void)
{
	struct addrinfo hints, *result, *rp;
	int sockfd=-1;

    initialize_openssl();
    pdata.ssl_ctx = create_ssl_context();
    configure_ssl_context(pdata.ssl_ctx);

	memset(&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	int s = getaddrinfo(NULL, port, &hints, &result);
	if(s != 0) {
		perror("getaddrinfo");
		exit(1);
	}

	for(rp = result; rp != NULL; rp = rp->ai_next) {
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if(sockfd == -1)
			continue;

		int yes = 1;
		if (setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if(bind(sockfd, rp->ai_addr, rp->ai_addrlen) == 0)
			break; // success

		close(sockfd);
	}
	if(rp == NULL) { // no address succeeded
		fprintf(stderr, "Could not bind\n");
		exit(1);
	}

	printf("Server is running on port %s.\n", port);
	freeaddrinfo(result);

	if(listen(sockfd, 1) == -1) {
		perror("listen");
		exit(1);
	}

	pdata.sockfd = sockfd;
	puts("Waiting for conections...");

	return sockfd;
}

static void set_signal_handler(int signum, const struct sigaction *sa)
{
	if (sigaction(signum, sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}
}

void set_signals(sdata_t *sdata)
{
	struct sigaction sa;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sa.sa_handler = sigpipe_handler;
	set_signal_handler(SIGPIPE, &sa);

	sa.sa_handler = sigchld_handler;
	set_signal_handler(SIGCHLD, &sa);

	sa.sa_flags |= SA_RESTART;
	sa.sa_handler = exit_program;
	set_signal_handler(SIGTERM, &sa);
	set_signal_handler(SIGINT, &sa);

	sa.sa_handler = dummy_handler;
	sa.sa_flags |= SA_NODEFER;
	/* Do not add the signal to the thread's signal mask  while the handler  is
	 * executing, unless the signal is specified in act.sa_mask.  Consequently,
     * a  further  instance  of the signal may be delivered to the thread while
     * it is executing the handler.
     */
	set_signal_handler(SIGCONT, &sa);

	sa.sa_flags |= SA_SIGINFO;
	/* TODO: Check the usage of SA_NODEFER flag here, it may be wrong */
	sa.sa_sigaction = &sigusr1_handler;
	set_signal_handler(SIGUSR1, &sa);

	on_exit(unmap_mem, sdata);           // 3°
	on_exit(close_connections, sdata);   // 2°
	on_exit(terminate_children, sdata);  // 1°
}

void* create_shared_memory(size_t size) {
  // Our memory buffer will be readable and writable:
  int protection = PROT_READ | PROT_WRITE;

  // The buffer will be shared (meaning other processes can access it), but
  // anonymous (meaning third-party processes cannot obtain an address for it),
  // so only this process and its children will be able to use it:
  int visibility = MAP_SHARED | MAP_ANONYMOUS;

  // The remaining parameters to `mmap()` are not important for this use case,
  // but the manpage for `mmap` explains their purpose.
  return mmap(NULL, size, protection, visibility, -1, 0);
}

void unmap_mem(int status, void* data)
{
	sdata_t *sdata = data;
	if(pdata.cid == 0) // only parent executes this code
	{
		write(1, "Unmapping shared memory...", 26);
		if(sdata) {
			if(sdata->message_mem) {
				munmap(sdata->message_mem, MESSAGES_MEM_SZ);
			}
			munmap(sdata, CLIENTS_MEM_SZ);
			sdata = NULL;
		}
		write(1," done.\n", 7);
	}
}

static void sigchld_handler(int signal)
{
	(void) signal;
//	wait_for_child(sdata);
	sigchld_received++;
}

//__attribute__((__noreturn__))
static void sigpipe_handler(int signal)
{
	(void)signal;
	sigpipe_received=1;
//	report_socket_down(sdata);
//	exit(0);
}

void close_connections(int status, void* data)
{
//	sdata_t *sdata = data; // server data
	struct process_data *p = &pdata; // process data

	if(pdata.cid == 0) // parent
	{
		if(p->sockfd != -1) { // 3
			close(p->sockfd);
			p->sockfd = -1;
		}
	}
	else // childrens
	{
		if(p->ssl != NULL) { // 1
			if(SSL_shutdown(p->ssl) == 0){
			//	shutdown(sockfd, SHUT_WR);
				sleep_ms(50);
				SSL_shutdown(p->ssl);
			}
			SSL_free(p->ssl);
			p->ssl = NULL;
		}
		if(p->sockfd != -1) { // 2
			close(p->sockfd);
			p->sockfd = -1;
		}
		if(p->ssl_ctx != NULL) { // 4
			SSL_CTX_free(p->ssl_ctx);
			p->ssl_ctx = NULL;
		}
		cleanup_openssl();
	}
	// TODO: no tendrían que ejecutar todos lo mismo? creo q el parent también tiene un SSL_CTX
}

void report_socket_down(sdata_t *sdata)
{
	int client_id = pdata.cid;
	char* buf = (char*) sdata->message_mem + MESSAGES_BUF_MEM;
	sprintf(buf, "Client %d disconnected.", client_id);

	puts(buf);
	send_echo(sdata, INFO, buf, client_id);
}

void wait_for_child(sdata_t *sdata)
{
	pid_t terminated_pid = wait(NULL);

	if(terminated_pid > 0) {
		int id = get_id_by_pid(sdata, terminated_pid);
		dbg_print("in wait_for_child(): removing client %d\n", id);
		remove_client(sdata, id);
	}
	else {
		perror("wait");
		exit(1); // is it an error? TODO: test with SIGSTOP
	}
}

void terminate_children(int status, void* data)
{
	sdata_t *sdata = data; // server data
	struct process_data *p = &pdata; // process data

	if(p->cid == 0) // only parent executes this code
	{
		write(1,"Terminating all child processes...", 34);

		// Disable SIGCHLD signal
		sigset_t set;
		sigemptyset(&set);
		sigaddset(&set, SIGCHLD);
		pthread_sigmask(SIG_BLOCK, &set, NULL);

		// Signal all children to terminate
		struct client *chead;
		for(chead = sdata->chead; chead != NULL; chead = chead->next)
			kill(chead->pdata->pid, SIGTERM);

		// Wait for all children termination
		while(sdata->chead != NULL) {
			sigchld_handler(0);
		}
		write(1, " done.\n", 7);
	}
}

__attribute__((__noreturn__))
void exit_program(int signal)
{
	(void)signal; // may be SIGTERM or SIGINT

	exit(0); // calling exit(0) produces further calls to
	         // terminate_children(), close_connections() and unmap_mem()
}

int kick_client(sdata_t *sdata, int id)
{
	pid_t pid = get_pid_by_id(sdata, id);
	if(pid == -1)
		return -1;
	kill(pid, SIGTERM);
	return 0;
}

int get_free_id(struct client *chead)
{
	int id;

	for(id=1; chead != NULL; ++id, chead=chead->next)
	{
		if(chead->pdata->cid > id)
			break;
	}

	return id;
}

pid_t get_pid_by_id(sdata_t *sdata, int id)
{
	struct client *c = sdata->chead;
	while(c) {
		if(c->pdata->cid == id)
			return c->pdata->pid;
		c = c->next;
	}
	return -1;
}

int get_id_by_pid(sdata_t *sdata, pid_t pid)
{
	struct client *c = sdata->chead;
	while(c) {
		if(c->pdata->pid == pid)
			return c->pdata->cid;
		c = c->next;
	}
	return -1;
}

char *get_ip_str(const struct sockaddr *sa, char *s, socklen_t maxlen)
{
	switch(sa->sa_family) {
		case AF_INET:
	        inet_ntop(AF_INET, &(((const struct sockaddr_in *)sa)->sin_addr)
			          , s, maxlen);
			break;

		case AF_INET6:
	        inet_ntop(AF_INET6, &(((const struct sockaddr_in6 *)sa)->sin6_addr)
			          , s, maxlen);
			break;

		default:
			strncpy(s, "Unknown AF", maxlen);
			return NULL;
	}

	return s;
}

void print_clients(sdata_t *sdata)
{
	struct client *chead = sdata->chead;
	int n = sdata->clients_cnt;
	printf("\n%d Client%s connected:\n", n, n == 1 ? "":"s");
	puts("cid\tpid\tuptime");
	for(chead = sdata->chead; chead != NULL; chead=chead->next)
	{
		struct process_data *p = chead->pdata;
		time_t uptime = time(NULL) - p->time_join;
		printf("%d\t%d\t%lds\n",
		       p->cid, p->pid, uptime);
	}
	puts("");
}

void print_uptime(sdata_t *sdata)
{
	printf("Uptime: %lds\n", time(NULL) - sdata->time_up);
}

void print_commands_help(void)
{
	puts("Command list:");
	puts("help ; info ; quit ; uptime ; sdata ; "
	     "stats|status ; say [msg] ; kick [cid]");
}

int check_id(sdata_t *sdata, int id)
{
	struct client *c = sdata->chead;
	while(c) {
		if(c->pdata->cid == id)
			return 0;
		c = c->next;
	}
	return -1;
}

int add_client(sdata_t *sdata, struct process_data *new_pdata)
{
	struct client *new, *aux = sdata->chead;
	int id = -1;

	if((size_t)sdata->clients_cnt >= MAX_CLIENTS)
		return id;

	id = get_free_id(sdata->chead);

	size_t mem = (size_t) sdata;
	mem += sizeof(sdata_t) +
			sizeof(struct client) * ((size_t)id-1);
	new = (struct client *) mem;

	new->pdata = new_pdata;
	new->next = NULL;

	if(aux == NULL || aux->pdata->cid > 1) {
		new->next = sdata->chead;
		sdata->chead = new;
	}
	else {
		while(aux->next && aux->next->pdata->cid < id) // TODO: simplificar esto plz con un aux_next
			aux = aux->next;
		new->next = aux->next;
		aux->next = new;
	}

	++sdata->clients_cnt;
	return id;
}

void remove_client(sdata_t *sdata, int id)
{
	struct client *aux = sdata->chead;
	struct client *del = NULL;
	if(aux == NULL)
		return;
	if(aux->pdata->cid == id) {
		del = aux;
		sdata->chead = aux->next;
		--sdata->clients_cnt;
	}
	else while(aux->next) {
		if(aux->next->pdata->cid == id) { // TODO: simplificar esto plz con un aux_next
			del = aux->next;
			aux->next = del->next;
			--sdata->clients_cnt;
			break;
		}
		aux = aux->next;
	}
	if(del)
		memset(del, 0, sizeof (struct client));
}

size_t getLine(char *buf, int buf_sz)
{
	if (fgets(buf, buf_sz, stdin) == NULL) {
		return 0;
	}

	size_t len = strlen(buf);
	if(len>0) {
		buf[--len] = '\0';

		if((int)len == buf_sz-1) {
			// Input bigger than buffer. Clean stdin
			int c;
			do {
				c = getchar();
			} while (c != '\n' && c != EOF);
		}
	}

	return len;
}

void print_all_messages(sdata_t *clients)
{
	struct message *msg = clients->mhead;
	puts("pending messages:\n");
	while(msg) {
		printf("\"%s\", from %d\n", msg->msg, msg->sender_id);
		msg = msg->next;
	}
}

struct message *get_message(sdata_t *sdata, int id)
{
	struct message *msg = sdata->mhead;

	while(msg && msg->sender_id != id)
		msg = msg->next;

	return (msg && msg->sender_id == id) ? msg : NULL;
}

struct message *push_msg(sdata_t *sdata, char *buf, size_t len,
                         int sender_id, int echos)
{
	struct message *new, *tail = sdata->mhead;

	size_t mem = (size_t) sdata->message_mem +
	             (size_t) sender_id * sizeof(struct message);
	new = (struct message*) mem;
	new->msg = buf;
	new->lenght = len;
	new->sender_id = sender_id;
	new->echos = echos;
	new->next = NULL;

	if(tail == NULL) {
		sdata->mhead = new;
	}
	else {
		while(tail->next)
			tail = tail->next;
		tail->next = new;
	}
	return new;
}

void pop_msg(sdata_t *sdata, int sender_id)
{
	struct message *aux = sdata->mhead;
	struct message *del = aux;

	if(aux == NULL)
		return;

	if(aux->sender_id == sender_id)
		sdata->mhead = aux->next;

	else while(aux->next) {
		if(aux->next->sender_id == sender_id) {
			del = aux->next;
			aux->next = del->next;
			break;
		}
		aux = aux->next;
	}

	memset(del, 0, sizeof (struct message));
}

struct msg_data {
	sdata_t *sdata;
	int sender_id;
};

int send_message(sdata_t *sdata, msg_type_t concept,
                 char *msg, int sender_id, int dest_id)
{
	char *buf = ((char*)sdata->message_mem) + MESSAGES_BUF_MEM;
	size_t len = strlen(msg)+1;
	pid_t dest_pid = get_pid_by_id(sdata, dest_id);

	if(dest_pid == -1 || sdata->clients_cnt == 0)
		return -1;

	if(concept == MESSAGE) {
		char tmp[16];
		size_t tmplen;
		if(sender_id == 0) {
			strcpy(tmp, "Server-> ");
			tmplen = 9;
		}
		else {
			tmplen = snprintf(tmp, sizeof(tmp), "Client %d-> ", sender_id);
		}
		memcpy(buf+tmplen, msg, len-1);
		memcpy(buf, tmp, tmplen);
		buf[len+tmplen-1] = '\0';
		len += tmplen;
	}
	else {
		memcpy(buf, msg, len);
	}

	struct message *m = push_msg(sdata, buf, len, sender_id, 1);

	struct msg_data mdata = {sdata, sender_id};
	union sigval value;
	value.sival_ptr = &mdata;

	if(sigqueue(dest_pid, SIGUSR1, value) == -1) {
		perror("sigqueue");
		return -1;
	}

	// Espero a que el mensaje se haya enviado al cliente. No retorno 
	// inmediatamente así no recibo más comandos hasta que no manejé el actual.
	while(atomic_load(&m->echos) > 0) {
		if(sleep(2) == 0) // sleep(1) doesn't work for this purpose
			break;        // timeout ~2 seconds reached
	}
	int ret = (atomic_load(&m->echos) == 0) ? 0 : -1;

	pop_msg(sdata, sender_id);
	return ret;
}

int send_echo(sdata_t *sdata, msg_type_t concept,
              const char *msg, int sender_id)
{
	struct client *chead;
	char *buf = ((char*)sdata->message_mem) + MESSAGES_BUF_MEM;
	size_t len = strlen(msg)+1;

	if(sdata->clients_cnt == 0)
		return -1;

	if(concept == MESSAGE) {
		char tmp[16];
		size_t tmplen;

		if(sender_id == 0) {
			strcpy(tmp, "Server-> ");
			tmplen = 9;
		}
		else {
			snprintf(tmp, sizeof(tmp), "Client %d-> ", sender_id);
			tmplen = strlen(tmp);
		}
		memcpy(buf+tmplen, msg, len-1);
		memcpy(buf, tmp, tmplen);
		buf[len+tmplen-1] = '\0';
		len += tmplen;
	}
	else {
		memcpy(buf, msg, len);
	}

	int n_echos = (sender_id == 0) ? sdata->clients_cnt : sdata->clients_cnt - 1;
	struct message *m = push_msg(sdata, buf, len, sender_id, n_echos);

	struct msg_data mdata = {sdata, sender_id};
	union sigval value;
	value.sival_ptr = &mdata;

	for(chead = sdata->chead; chead != NULL; chead = chead->next)
	{
		if(chead->pdata->cid != sender_id)
		{
			if(sigqueue(chead->pdata->pid, SIGUSR1, value) == -1)
				perror("sigqueue");
		}
	}

	// Espero a que el mensaje se haya enviado a todos los clientes. No retorno
	// inmediatamente así no recibo más mensajes hasta que no manejé el actual.
	while(atomic_load(&m->echos) > 0) {
		if(sleep(2) == 0) // sleep(1) doesn't work for this purpose
			break;        // timeout ~2 seconds reached
	}
	int ret = (atomic_load(&m->echos) == 0) ? 0 : -1;

	pop_msg(sdata, sender_id);
	return ret;
}

static void sigusr1_handler(int signal, siginfo_t *info, void *ucontext)
{
	(void)signal; (void)ucontext;
	struct msg_data *mdata = info->si_value.sival_ptr;

	struct message *msg = get_message(mdata->sdata, mdata->sender_id);
	if(msg == NULL) {
		fputs("Unable to echo msg.\n", stderr);
		return;
	}

	char *buf = msg->msg;
	int len = (int) msg->lenght;

	//ssize_t ret = send(cfd, buf, len, MSG_DONTWAIT);
	ssize_t ret = SSL_write(pdata.ssl, buf, len);
	// TODO: evaluate how to use MSG_DONTWAIT flag with fcntl(fd)
	if(ret <= 0) {
		perror("SSL_write");
		exit(1);
	}
	atomic_fetch_sub(&msg->echos, 1);
	kill(info->si_pid, SIGCONT); // wake up from sleep()
}

static void dummy_handler(int s){(void)s;}

void sleep_ms(int ms)
{
	struct timespec tim, rem;
	tim.tv_sec = ms / 1000;
	tim.tv_nsec = (ms % 1000) * 1000000;

	if(nanosleep(&tim , &rem) == -1)
	{
		if (errno == EINTR)
			sleep_ms(rem.tv_sec*1000 + rem.tv_nsec/1000000);
		
		else
			perror("nanosleep");
	}
}

/* --- OpenSSL --- */

void initialize_openssl() {
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
	ERR_free_strings();
	EVP_cleanup();
}

SSL_CTX *create_ssl_context() {
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

void configure_ssl_context(SSL_CTX *ctx) {
	// Use certificates (make sure to create the certificates)
	SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);
/*
# interactive
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365

# non-interactive and 10 years expiration
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 
-days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=Company
SectionName/CN=CommonNameOrHostname"
*/
}
