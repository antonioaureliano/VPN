#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include <openssl/rsa.h>       /* SSLeay stuff */
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

/* SSL defines */
#define CLI_CERTF "client.crt"
#define CLI_KEYF "client.key"
#define SERV_CERTF "server.crt"
#define SERV_KEYF "server.key"
#define CACERT "ca.crt"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }


int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  
	int tap_fd;
	int option;
	int flags = IFF_TUN;
	int header_len = IP_HDR_LEN;
	int maxfd;
	int sock_fd;
	int net_fd;
	int optval = 1;
	int cliserv = -1;    /* must be specified on cmd line */
	int err;
	int err2;
	int listen_sd;
	uint16_t nread;
	uint16_t nwrite;
	uint16_t plength;
	uint16_t total_len;
	uint16_t ethertype;
	unsigned short int port = PORT;
	unsigned long int tap2net = 0; 
	unsigned long int net2tap = 0;
	char buffer[BUFSIZE];
	char if_name[IFNAMSIZ] = "";
	char remote_ip[16] = "";
	char *str;
	char buf [4096];
	socklen_t remotelen;
	socklen_t client_len;
	struct sockaddr_in local, remote;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	SSL_CTX *ctx;
	SSL *ssl;
	X509 *client_cert;
	X509 *server_cert;
	const SSL_METHOD *meth;

	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);

	CHK_NULL(ctx);
	CHK_SSL(err);
	
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

	progname = argv[0];

	/* Check command line options */
	while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
		switch(option) {
			case 'd':
				debug = 1;
				break;
			case 'h':
				usage();
				break;
			case 'i':
				strncpy(if_name,optarg,IFNAMSIZ-1);
				break;
			case 's':
				cliserv = SERVER;
				break;
			case 'c':
				cliserv = CLIENT;
				strncpy(remote_ip,optarg,15);
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'u':
				flags = IFF_TUN;
				break;
			case 'a':
				flags = IFF_TAP;
				header_len = ETH_HDR_LEN;
				break;
			default:
				my_err("Unknown option %c\n", option);
				usage();
		}
	}

	argv += optind;
	argc -= optind;

	if(argc > 0){
		my_err("Too many options!\n");
		usage();
	}

	if(*if_name == '\0'){
		my_err("Must specify interface name!\n");
		usage();
	}
	else if(cliserv < 0){
		my_err("Must specify client or server mode!\n");
		usage();
	}
	else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
		my_err("Must specify server address!\n");
		usage();
	}

	/* initialize tun/tap interface */
	if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
		my_err("Error connecting to tun/tap interface %s!\n", if_name);
		exit(1);
	}

	do_debug("Successfully connected to interface %s\n", if_name);

	/* TCP socket for both client and server */
	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(sock_fd, "socket");

	if(cliserv==CLIENT){
	
		/* Client, try to connect to server */

		/* assign the destination address */
		memset(&remote, 0, sizeof(remote));
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = inet_addr(remote_ip);
		remote.sin_port = htons(port);

		err = connect(sock_fd, (struct sockaddr*) &remote ,sizeof(remote)); 
		CHK_ERR(err, "connect");
		
		/* Now we have TCP conncetion. Start SSL negotiation. */
		
		/* Does this also perform authentication or do we need to 
		 * program the authentication steps explicitly? Or do we ask
		 * the client for username and password?
		 */
		ssl = SSL_new(ctx);
		CHK_NULL(ssl);
		SSL_set_fd(ssl, sock_fd);
		err = SSL_connect(ssl);
		//CHK_SSL(err);
		err2 = SSL_get_error(ssl, err);
		printf("The error is %d\n", err2);

		net_fd = sock_fd;
		//net_fd = err?
		do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
		
		//Criar socket UDP para transmissão pelo túnel
		
		/* We could do all sorts of certificate verification stuff here before
     	deallocating the certificate. */

		//X509_free (server_cert);

	} else {
	
		/* Server, wait for connections */

		/* set the local certificate from CertFile */
		if (SSL_CTX_use_certificate_file(ctx, SERV_CERTF, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(-2);
		}
		/* set the private key from KeyFile (may be the same as CertFile) */
		if (SSL_CTX_use_PrivateKey_file(ctx, SERV_KEYF, SSL_FILETYPE_PEM) <= 0) {
			ERR_print_errors_fp(stderr);
			exit(-3);
		}
		/* verify private key */
		if (!SSL_CTX_check_private_key(ctx)) {
			printf("Private key does not match the certificate public keyn");
			exit(-4);
		}

		/* avoid EADDRINUSE error on bind() */
		if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
		  perror("setsockopt()");
		  exit(1);
		}

		memset(&local, 0, sizeof(local));
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = htonl(INADDR_ANY);
		local.sin_port = htons(port);
		
		err = bind(sock_fd, (struct sockaddr*) &local, sizeof(local));                   
		CHK_ERR(err, "bind");

		err = listen(sock_fd, 5);
		CHK_ERR(err, "listen");

		/* wait for connection request */
		client_len = sizeof(remote);
		memset(&remote, 0, client_len);
		net_fd = accept(sock_fd, (struct sockaddr*) &remote, &client_len);
		CHK_ERR(net_fd, "accept");
		
		/* TCP connection is ready. Do server side SSL. */
		ssl = SSL_new(ctx);
		CHK_NULL(ssl);
		SSL_set_fd(ssl, net_fd);
		err = SSL_accept(ssl);
		do_debug("Error code = %d\n", err);
		err2 = SSL_get_error(ssl,err);
		do_debug("The error is %d\n", err2);
		//CHK_SSL(err);

		do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
	}

	/* use select() to handle two descriptors at once */
	maxfd = (tap_fd > net_fd)?tap_fd:net_fd;

	while(1) {
		int ret;
		fd_set rd_set;

		FD_ZERO(&rd_set);
		FD_SET(tap_fd, &rd_set); 
		FD_SET(net_fd, &rd_set);

		ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

		if (ret < 0 && errno == EINTR){
		  continue;
		}

		if (ret < 0) {
		  perror("select()");
		  exit(1);
		}

		if(FD_ISSET(tap_fd, &rd_set)){
		  /* data from tun/tap: just read it and write it to the network */
		  
		  nread = cread(tap_fd, buffer, BUFSIZE);

		  tap2net++;
		  do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

		  /* write length + packet */
		  plength = htons(nread);
		  nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
		  nwrite = cwrite(net_fd, buffer, nread);
		  
		  do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
		}

		if(FD_ISSET(net_fd, &rd_set)){
		  /* data from the network: read it, and write it to the tun/tap interface. 
		   * We need to read the length first, and then the packet */

		  /* Read length */      
		  nread = read_n(net_fd, (char *)&plength, sizeof(plength));
		  if(nread == 0) {
			/* ctrl-c at the other end */
			break;
		  }

		  net2tap++;

		  /* read packet */
		  nread = read_n(net_fd, buffer, ntohs(plength));
		  do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

		  /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
		  nwrite = cwrite(tap_fd, buffer, nread);
		  do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
		}
	}
	
	SSL_shutdown (ssl);
	close(sock_fd);
	SSL_free (ssl);
	SSL_CTX_free(ctx);        /* release context */

	return(0);
}
