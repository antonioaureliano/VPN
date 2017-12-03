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
#include <memory.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 4096   
#define PORT 1111

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

#define CERTF "client.crt"
#define KEYF "client.key"
#define CACERT "ca.crt"

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

int main(int argc, char *argv[]) {

	int tap_fd;
	int net_fd;
	int maxfd;
	int flags = IFF_TUN;
	int header_len = ETH_HDR_LEN;
	int err;
	uint16_t nread;
	uint16_t nwrite;
	uint16_t plength;
	char *str;
	char if_name[IFNAMSIZ] = "";
	char remote_ip[16] = "";
	char buffer[BUFSIZE];
	unsigned long int tap2net = 0;
	unsigned long int net2tap = 0;
	struct sockaddr_in remote;
	socklen_t remotelen;
	SSL_CTX *ctx;
	SSL *ssl;
	X509 *server_cert;
	const SSL_METHOD *meth;

	if(argc > 3){
    	perror("Too many options!");
    	exit(1);
    }
    
    strcpy(if_name, argv[1]);        
    strcpy(remote_ip, argv[2]);
    
    if(*if_name == '\0'){
		perror("Must specify interface name!");
		exit(1);
	}else if(*remote_ip == '\0'){
		perror("Must specify server address!");
		exit(1);
	} 
     
	/* initialize tun/tap interface */
	if ((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0) {
		printf("Error connecting to tun/tap interface %s!\n", if_name);
		exit(1);
	}

	printf("Successfully connected to interface %s\n", if_name);   
	
	SSLeay_add_ssl_algorithms();
	meth = SSLv23_client_method();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(meth);
	
	if((ctx) == NULL) {
		exit (1);
	}
	
	if((err)==-1) { 
		ERR_print_errors_fp(stderr); 
		exit(2); 
	}
	
	SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
	SSL_CTX_load_verify_locations(ctx,CACERT,NULL);

	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-2);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(-3);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate public keyn");
		exit(-4);
	}
	
	if ((net_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket()");
		exit(1);
	}

    /* assign the destination address */
    memset(&remote, '\0', sizeof(remote));
    remote.sin_family 		= AF_INET;
    remote.sin_addr.s_addr 	= inet_addr(remote_ip);
    remote.sin_port 		= htons(PORT);

    /* connection request */
    if(err = connect(net_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0){
		perror("connect()");
		exit(1);
    }
    
    printf("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
    
    /* Now we have TCP conncetion. Start SSL negotiation. */
    
	ssl = SSL_new(ctx);
	
	if ((ssl) == NULL) {
		exit (1);
	}
	
	SSL_set_fd(ssl, net_fd);
	err = SSL_connect (ssl);
	
	if ((err)==-1) { 
		ERR_print_errors_fp(stderr); 
		exit(2); 
	}
	
	/* Get the cipher - opt */

	printf("SSL connection using %s\n", SSL_get_cipher (ssl));

	/* Get server's certificate (note: beware of dynamic allocation) - opt */

	server_cert = SSL_get_peer_certificate (ssl); 
	      
	if ((server_cert) == NULL) {
		exit (1);
	}
	printf("Server certificate:\n");

	str = X509_NAME_oneline(X509_get_subject_name(server_cert),0,0);
	
	if ((str) == NULL) {
		exit (1);
	}
	
	printf("\t subject: %s\n", str);
	
	OPENSSL_free (str);

	str = X509_NAME_oneline (X509_get_issuer_name  (server_cert),0,0);
	
	if ((str) == NULL) {
		exit (1);
	}
	
	printf("\t issuer: %s\n", str);
	
	OPENSSL_free(str);
	
	/* We could do all sorts of certificate verification stuff here before
     deallocating the certificate. */
	
	X509_free (server_cert);
	
    
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
			printf("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

			err = SSL_write (ssl, buffer, (sizeof(buffer) - 1));
			nwrite = err;
			
			if ((err)==-1) { 
				ERR_print_errors_fp(stderr); 
				exit(2); 
			}

			printf("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
		}

		if(FD_ISSET(net_fd, &rd_set)){
			/* data from the network: read it, and write it to the tun/tap interface. 
			* We need to read the length first, and then the packet */

			err = SSL_read(ssl, buffer, (sizeof(buffer) - 1));
			buffer[err] = '\0';
			
			if(err == 0) {
				/* ctrl-c at the other end */
				break;
			}
				
			nread = err;
			net2tap++;
			
			printf("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

			/* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
			nwrite = cwrite(tap_fd, buffer, nread);
			printf("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
		}
	}
	
	/* Clean up */
	SSL_shutdown(ssl);
	close(net_fd);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	
	return(0);

}

        
