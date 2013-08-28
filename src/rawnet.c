#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <readline/readline.h>
#include <readline/history.h>

#define ERR(...) fprintf (stderr, __VA_ARGS__)
#define INFO(...) fprintf (stderr, __VA_ARGS__)
#define DEBUG(...) fprintf (stderr, __VA_ARGS__)

#define MAX_ADDR_STR (INET6_ADDRSTRLEN + 7)
#define DEFAULT_HISTORY_FILE "/.rawnet_history"
#define INPUT_BUFFER_SIZE 256

void
usage(char *prg)
{
  INFO("usage: %s [-hvbu6c] [-l <local addr]> [-p <local port>] [<addr> <port>]\n",prg);
  INFO("\t-v\tVerbose\n");
  INFO("\t-u\tUse UDP instead of TCP\n");
  INFO("\t-6\tUse IPv6 instead of IPv4\n");
  INFO("\t-b\tAllow broadcast\n");
  INFO("\t-c\tQuit when closing\n");
  INFO("\t-h\tThis help\n");
}

#define VERBOSE_PRINT_ADDR 1
#define VERBOSE_PRINT_CONNECTION 1

#define PRINT_TEXT	0x08
#define PRINT_HEX	0x10
#define PRINT_OCT	0x20
#define PRINT_DEC	0x30
#define PRINT_BIN	0x40
#define PRINT_BASE_MASK	0x70

#define FLAG_LISTEN 0x01
#define FLAG_UDP 0x02
#define FLAG_IPV6 0x04
#define FLAG_BROADCAST 0x100
#define FLAG_QUITONCLOSE 0x200

typedef struct AppContext AppContext;
struct AppContext
{
  struct sockaddr *remote_addr;
  socklen_t remote_addr_len;
  struct sockaddr *local_addr;
  socklen_t local_addr_len;
  int verbosity;
  unsigned int flags;
  int netfd;
  int acceptfd;
  unsigned int max_bytes_per_line;
  int input_state;
  char *history_file;
  int running;
};

static void
clear_app(AppContext *app)
{
  if (app->remote_addr) 
    free(app->remote_addr);
  if (app->local_addr)
    free(app->local_addr);
  if (app->netfd >= 0) {
    close(app->netfd);
  }
  if (app->acceptfd >= 0) {
    close(app->acceptfd);
  }
  if (app->history_file) {
    free(app->history_file);
  }
}

static void 
init_app(AppContext *app)
{
  app->remote_addr = NULL;
  app->remote_addr_len = 0;
  app->local_addr = NULL;
  app->local_addr_len = 0;
  app->verbosity = 0;
  app->flags = PRINT_HEX | PRINT_TEXT;
  app->max_bytes_per_line = 16;
  app->netfd = -1;
  app->acceptfd = -1;
  app->input_state = 0;
  app->history_file = NULL;
}

static char *
get_addr_str(struct sockaddr *addr, char *buffer, size_t len)
{
  /* This is only strictly correct for IPv4 but the offsets should be the
     same for IPv6 */
  struct sockaddr_in *a = (struct sockaddr_in*)addr;
  if (inet_ntop(a->sin_family, &a->sin_addr,
		buffer, len)) {
    size_t end = strlen(buffer);
    snprintf(buffer + end, len - end, " %d", ntohs(a->sin_port));
  } else {
    strncpy(buffer, "(invalid)", len);
  }
  return buffer;
}
static socklen_t
build_sock_addr(struct sockaddr **addrp,
		const char *addr_str, const char *port_str, int flags)
{
  struct addrinfo *ai;
  struct addrinfo hint;
  socklen_t addr_len;
  int res;
  if (flags & FLAG_IPV6)
    hint.ai_family = AF_INET6;
  else
    hint.ai_family = AF_INET;
  if (flags & FLAG_UDP)
    hint.ai_socktype = SOCK_DGRAM;
  else
    hint.ai_socktype = SOCK_STREAM;
  hint.ai_protocol = 0;
  hint.ai_flags = AI_PASSIVE;
  res = getaddrinfo(addr_str, port_str, &hint, &ai);
  if (res) {
    ERR( "Failed to resolve address or port: %s\n", gai_strerror(res));
    return 0;
  }
  addr_len = ai->ai_addrlen;
  *addrp = malloc(addr_len);
  memcpy(*addrp, ai->ai_addr, addr_len);
  freeaddrinfo(ai);
  return addr_len;
}

static int
make_connection(AppContext *app)
{
    sa_family_t family;
  if (!app->local_addr && !app->remote_addr) {
    ERR( "No local or remote address\n");
    return 0;
  }
  if (app->local_addr) family = app->local_addr->sa_family;
  else family = app->remote_addr->sa_family;
      
  if (app->flags & FLAG_UDP) {
    /* UDP */
    app->netfd = socket(family, SOCK_DGRAM, 0);
    if (!app->netfd) {
      ERR( "Failed to create socket: %s\n", strerror(errno));
      return 0;
    }
    if (app->local_addr) {
      if (bind(app->netfd, app->local_addr, app->local_addr_len)) {
	ERR( "Failed to bind to local address: %s\n", strerror(errno));
	return 0;
      }
    }
    if (app->flags & FLAG_BROADCAST) {
      static const int on = 1;
      if (setsockopt(app->netfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(int))) {
	ERR( "Failed set broadcast flag on socket: %s\n", strerror(errno));
	return 0;
      }
    }
  } else {
    /* TCP */
    app->netfd = socket(family, SOCK_STREAM, 0);
    if (!app->netfd) {
      ERR( "Failed to create socket: %s\n", strerror(errno));
      return 0;
    }
    if (app->local_addr) {
      if (bind(app->netfd, app->local_addr, app->local_addr_len)) {
	ERR( "Failed to bind to local address: %s\n", strerror(errno));
	
	return 0;
      }
    }
    if (app->remote_addr) {
      if (connect(app->netfd, app->remote_addr, app->remote_addr_len)) {
	ERR( "Failed to connect to remote address: %s\n", strerror(errno));
	return 0;
      }
    } else {
      if (listen(app->netfd, 2)) {
	ERR( "Failed to listen: %s\n", strerror(errno));
	return 0;
      }
      app->acceptfd = app->netfd;
      app->netfd = -1;
    }
  }
  if (app->netfd >= 0) {
    if (fcntl(app->netfd, F_SETFL, O_NONBLOCK) < 0) {
      ERR( "Failed to set nonblocking mode: %s\n", strerror(errno));
      return 0;
    }
  }
  return 1;
}

static void
print_data_block(FILE *file, unsigned char *buffer, unsigned int len,
		 char *prefix, unsigned int max_per_line, unsigned int flags)
{
  while(len > 0) {
    unsigned int line_len = (len > max_per_line) ? max_per_line : len;
    unsigned int chars_printed = 0;
    unsigned int chars_per_byte;
    unsigned int b;
    fputs(prefix,file);
    switch(flags & PRINT_BASE_MASK) {
    case PRINT_HEX:
      for(b = 0; b < line_len; b++) fprintf(file," %02x",buffer[b]);
      chars_per_byte = 3;
      break;
    case PRINT_DEC:
      for(b = 0; b < line_len; b++) fprintf(file," %03d",buffer[b]);
      chars_per_byte = 4;
      break;
    case PRINT_BIN:
      for(b = 0; b < line_len; b++) {
	unsigned char c = buffer[b];
	unsigned int bit;
	fputc(' ',file);
	for (bit = 0; bit < 8; bit++) {
	  fputc(((c & 0x80) ? '1' : '0'), file);
	  c <<= 1;
	}
      }
      chars_per_byte = 9;
      break;
    case PRINT_OCT:
      for(b = 0; b < line_len; b++) fprintf(file," %03o",buffer[b]);
      chars_per_byte = 4;
      break;
    default:
      chars_per_byte = 0;
    }
    chars_printed += chars_per_byte * line_len;
    while(chars_printed < chars_per_byte * max_per_line) {
      fputc(' ',file);
      chars_printed++;
    }
    if (flags & PRINT_TEXT) {
      fputc(' ',file);
      for(b = 0; b < line_len; b++) {
	if (buffer[b] >= ' ' && buffer[b] <= 0x7f) {
	  fputc(buffer[b],file);
	} else {
	  fputc('.', file);
	}
      }
      chars_printed += line_len + 1;
    }
    fputc('\n',file);
    len -= line_len;
    buffer += line_len;
  }
}

static void
send_data(AppContext *app, uint8_t *buffer, size_t len)
{
  if (app->netfd < 0 || !app->remote_addr) {
    ERR("No connection\n");
    return;
  }
  if (app->flags & FLAG_UDP) {
    /* UDP */
    if (sendto(app->netfd, buffer, len, 0,
	       app->remote_addr, app->remote_addr_len)<0) {
      ERR("sendto failed: %s\n", strerror(errno));
      return;
    }
  } else {
    /* TCP */
    while(len > 0) {
      int written = write(app->netfd, buffer, len);
      if (written < 0) {
	ERR("write failed: %s\n", strerror(errno));
	return;
	return;
      }
      buffer += written;
      len -= written;
    }
  }
}

static void
handle_net(AppContext *app)
{
  uint8_t buffer[2048];
  while(1) {
    ssize_t r;
    if (app->flags & FLAG_UDP) {
      struct sockaddr_in6 src_addr; /* It's also big enough for sockaddr_in */
      socklen_t addr_len = sizeof(src_addr);
      r= recvfrom(app->netfd, buffer, sizeof(buffer), 0,
		  (struct sockaddr*)&src_addr , &addr_len);
      if (r < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK) break;
	ERR("recvfrom failed: %s\n", strerror(errno));
	break;
      }
      if (!app->remote_addr) {
	app->remote_addr = malloc(addr_len);
	app->remote_addr_len = addr_len;
	memcpy(app->remote_addr, &src_addr, addr_len);
	if (app->verbosity >= VERBOSE_PRINT_ADDR) {
	  char addr_buffer[MAX_ADDR_STR];
	  INFO("Remote address: %s\n",
	       get_addr_str(app->remote_addr, addr_buffer,
			    sizeof(addr_buffer)));
	}
      }
    } else {
      r = read(app->netfd, buffer, sizeof(buffer));
      if (r < 0) {
	if (errno == EAGAIN || errno == EWOULDBLOCK) break;
	ERR("read failed: %s\n", strerror(errno));
	break;
      }
      if (r == 0) {
	close(app->netfd);
	app->netfd = -1;
	free(app->remote_addr);
	app->remote_addr = NULL;
	if (app->flags & FLAG_QUITONCLOSE) {
	  app->running = 0;
	}
	if (app->verbosity >= VERBOSE_PRINT_CONNECTION) {
	  INFO("Connection closed\n");
	}
	break;
      }
    }
    if (r > 0) 
      print_data_block(stdout, buffer, r, "", app->max_bytes_per_line,
		       app->flags);
  }
}
static void
handle_accept(AppContext *app)
{
  struct sockaddr_in6 raddr;
  socklen_t raddr_len = sizeof(raddr);
  int fd;
  fd = accept(app->acceptfd, (struct sockaddr*)&raddr, &raddr_len);
  if (fd < 0) {
    ERR("Failed to accept connection: %s\n", strerror(errno));
    return;
  }
  if (app->netfd > 0) {
    close(fd);
    if (app->verbosity >= VERBOSE_PRINT_CONNECTION) {
      char addr_str[MAX_ADDR_STR];
      INFO("Rejected connection from: %s\n",
	   get_addr_str((struct sockaddr*)&raddr, addr_str, sizeof(addr_str)));
    }
    return;
  }
  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
    close(fd);
    ERR( "Failed to set nonblocking mode for accepted connection: %s\n",
	 strerror(errno));
    return;
  }
  app->netfd = fd;
  app->remote_addr = malloc(raddr_len);
  app->remote_addr_len = raddr_len;
  memcpy(app->remote_addr, &raddr, raddr_len);

  if (app->verbosity >= VERBOSE_PRINT_CONNECTION) {
    char addr_str[MAX_ADDR_STR];
    INFO("Connection from: %s\n",
	 get_addr_str((struct sockaddr*)&raddr, addr_str, sizeof(addr_str)));
  }
}

static void
handle_input(AppContext *app)
{
  if (!app->input_state) {
    fprintf(stdout,"\n");
    rl_on_new_line();
    app->input_state = 1;
  }
  rl_callback_read_char ();
}


#define FD_NET 0
#define FD_ACCEPT 1
#define FD_INPUT 2

static void
event_loop(AppContext *app)
{
  struct pollfd fds[3];
  fds[FD_NET].events = POLLIN;
  fds[FD_ACCEPT].events = POLLIN;
  fds[FD_ACCEPT].fd = app->acceptfd;
  fds[FD_ACCEPT].revents = 0;;
  fds[FD_INPUT].events = POLLIN;
  fds[FD_INPUT].fd = STDIN_FILENO;

  app->running = 1;
  while(app->running) {
    fds[FD_NET].fd = app->netfd;
    fds[FD_NET].revents = 0;
    if (poll(fds,3, -1) >= 0) {
      if (fds[FD_INPUT].revents & POLLIN) {
	handle_input(app);
      }
      if (fds[FD_NET].revents & POLLIN) {
	handle_net(app);
      }
      if (fds[FD_ACCEPT].revents & POLLIN) {
	handle_accept(app);
      }
      
    } else {
      ERR("\npoll failed: %s\n", strerror(errno));
    }
  }
}

static AppContext app;

struct DynBuffer
{
  unsigned char *buffer;
  unsigned char *end;
  unsigned char *pos;
};

static void
add_to_buffer(struct DynBuffer *buffer,unsigned char *b, unsigned int len)
{
  if (buffer->buffer == NULL) {
    unsigned int size = INPUT_BUFFER_SIZE;
    if (size < len) size = len;
    buffer->buffer = (unsigned char*)malloc(size);
    buffer->pos = buffer->buffer;
    buffer->end = buffer->buffer + size;
  } else if (len > buffer->end - buffer->pos) {
    unsigned int size = (buffer->end - buffer->buffer) * 2;
    unsigned int buf_len = buffer->pos - buffer->buffer;
    if (size < buf_len + len) size = buf_len + len;
    buffer->buffer = realloc(buffer->buffer, size);
    if (!buffer->buffer) {
      ERR("Failed to allocate more memory for output buffer\n");
      exit(EXIT_FAILURE);
    }
    buffer->pos = buffer->buffer + buf_len;
    buffer->end = buffer->buffer + size;
  }
  memcpy(buffer->pos, b, len);
  buffer->pos += len;
}

static void 
init_buffer(struct DynBuffer *buffer)
{
  buffer->pos = buffer->buffer;
}

static void
add_history_if_different(const char *string)
{
  HIST_ENTRY* hist = history_get(history_base  + history_length - 1);
  /* Check if string is equal to last line in history. */
  if (*string == '\0' || (hist && strcmp(hist->line, string) == 0)) return;
  add_history(string);
}

inline void
skip_white(char **bufp)
{
  char *buf = *bufp;
  while(isspace(*buf)) buf++;
  *bufp = buf;
}

inline int
gethex(char ch)
{
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return (ch - 'a') + 10;
  if (ch >= 'A' && ch <= 'F') return (ch - 'A') + 10;
  return -1;
}

void
line_handler(char *line)
{
  static struct DynBuffer buffer = {NULL,NULL,NULL};
  if (!line) {
    app.running = 0;
    return;
  }

  add_history_if_different (line);

  init_buffer(&buffer);
  while(1) {
    int v;
    skip_white(&line);
    if (*line == '\0') break;
    v = gethex(*line);
    if (v < 0) {
      if (*line == '"') {
	line++;
	while(*line != '\0') {
	  unsigned char b;
	  if (*line == '\\') {
	    if (*++line == '\0') break;
	  } else if (*line == '"') {
	    line++;
	    break;
	  }
	  b = *line;
	  add_to_buffer(&buffer, &b, 1);
	  line++;
	}
      } else {
	ERR("'%c' is not a hex character\n", *line);
	return;
      }
    } else {
      unsigned char tot = 0;
      do {
	tot = tot * 16 + v;
	v = gethex(*(++line));
      } while(v >= 0);
      add_to_buffer(&buffer, &tot, 1);
    }
  }
  print_data_block(stdout,buffer.buffer,buffer.pos - buffer.buffer,"->",16,
		   PRINT_TEXT | PRINT_HEX);
  send_data(&app, buffer.buffer,buffer.pos - buffer.buffer);
}

static void
setup_readline(AppContext *app)
{
  if (!app->history_file) {
    const char* home = getenv("HOME");
    size_t len = strlen(home);
    app->history_file = malloc(len + sizeof(DEFAULT_HISTORY_FILE));
    strcpy(app->history_file, home);
    strcpy(app->history_file + len, DEFAULT_HISTORY_FILE);
  }
  rl_callback_handler_install ("> ", line_handler);
  using_history();
  stifle_history(100);
  read_history(app->history_file);
  history_set_pos(history_length);
}

int
main(int argc, char *argv[])
{
  int ch;
  const char *local_addr_str = NULL;
  const char *local_port_str = NULL;
  init_app(&app);
  while((ch = getopt(argc,argv,"hvu6bcl:p:")) != EOF) {
    switch(ch) {
    case 'v':
      app.verbosity++;
      break;
    case 'h':
      usage(argv[0]);
      clear_app(&app);
      exit(EXIT_SUCCESS);
    case 'u':
      app.flags |= FLAG_UDP;
      break;
    case '6':
      app.flags |= FLAG_IPV6;
      break;
    case 'l':
      local_addr_str = optarg;
      break;
    case 'b':
      app.flags |= FLAG_BROADCAST;
      break;
    case 'c':
      app.flags |= FLAG_QUITONCLOSE;
      break;
    case 'p':
      local_port_str = optarg;
      break;
    case '?':
      usage(argv[0]);
      clear_app(&app);
      exit(EXIT_FAILURE);
    }
  }
    
  if (argc != optind && argc != optind + 2) {
    usage(argv[0]);
    clear_app(&app);
    exit(EXIT_FAILURE);
  }

  if (local_addr_str && ! local_port_str) {
    ERR( "No local port given\n");
    clear_app(&app);
    exit(EXIT_FAILURE);
  }
  if (local_addr_str || local_port_str) {
    app.local_addr_len =
      build_sock_addr(&app.local_addr, local_addr_str, local_port_str,
		      app.flags);
    if (app.local_addr_len == 0) {
      clear_app(&app);
      exit(EXIT_FAILURE);
    }
    if (app.verbosity >= VERBOSE_PRINT_ADDR) {
      char addr_buffer[MAX_ADDR_STR];
      INFO("Local address: %s\n",
	   get_addr_str(app.local_addr, addr_buffer,
			sizeof(addr_buffer)));
    }
  }

  if (argc == optind + 2) {
    app.remote_addr_len =
      build_sock_addr(&app.remote_addr, argv[optind], argv[optind + 1],
		      app.flags);
    if (app.remote_addr_len == 0) {
      clear_app(&app);
      exit(EXIT_FAILURE);
    }
    if (app.verbosity >= VERBOSE_PRINT_ADDR) {
      char addr_buffer[MAX_ADDR_STR];
      INFO("Remote address: %s\n",
	   get_addr_str(app.remote_addr, addr_buffer,
			sizeof(addr_buffer)));
    }
  }
  if (!make_connection(&app)) {
    clear_app(&app);
    exit(EXIT_FAILURE);
  }
  setup_readline(&app);
  event_loop(&app);

  write_history(app.history_file);
  rl_callback_handler_remove ();
  
  clear_app(&app);
  INFO( "\nExiting\n");
  return EXIT_SUCCESS;
}
