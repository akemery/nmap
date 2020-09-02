#include "picotls.h"
#include "picotls/openssl.h"
#include "containers.h"

#define NB_ADDRESS_MAX    15
#define ADDRESS_SIZE      15
#define V6_ADDRESS_SIZE   40
#define NCAT_TCPLS_HANDSHAKE_COMPLETED 0
#define NCAT_TCPLS_PENDING_WRITE  30
#define NCAT_TCPLS_PENDING_READ  20
#define NCAT_TCPLS_HANDSHAKE_IN_PROGRESS  -20
#define TCPLS_HANDSHAKE_OR_MPJOIN_NOT_DONE -100

union sockaddr_u peer_addrs[NB_ADDRESS_MAX];
union sockaddr_u ours_addrs[NB_ADDRESS_MAX];

list_t *peers_list;
list_t *ours_list;
list_t *peers6_list;
list_t *ours6_list;
int nb_ours, nb_peers, nb_ours6, nb_peers6;
int listenfd[NB_ADDRESS_MAX];
struct tcpls_options *tcpls_o;


int tcpls_get_addrsv2(int af, unsigned int ours, char *optarg);
int do_tcpls_add_addrs(unsigned int is_server, tcpls_t * ctcpls);
int do_tcpls_bind(fd_list_t *client_fdlist, fd_set *master_readfds, fd_set *listen_fds);
ptls_context_t *ptls_ctx_new(void);
void ptls_ctx_free(ptls_context_t *ptls_ctx);
ptls_context_t *set_tcpls_ctx_options(int is_server);
int do_tcpls_accept(int socket, struct sockaddr *sockaddr, socklen_t  *sslen, int *is_primary, struct fdinfo *fdi);
int do_init_tcpls(int is_server);
int do_tcpls_handshake(struct fdinfo *fdi);
size_t tcpls_write(int cfd, struct fdinfo *fdi);
int tcpls_connexion_migration(int bytes_sent, tcpls_t *tcpls);
int do_tcpls_connect(nsock_pool nsp, nsock_iod nsiod, nsock_ev_handler handler, struct conn_state *cs);

struct tcpls_options{
    int timeoutval;
    unsigned int second;
    unsigned int nb_peers;
    unsigned int nb_ours;
};

struct tcpls_con {
    int sd;
    int transportid;
    unsigned int is_primary : 1;
    streamid_t streamid;
    unsigned int wants_to_write : 1;
    tcpls_t *tcpls;
    struct fdinfo *fdi;
};

struct cli_data {
  list_t *socklist;
  list_t *streamlist;
  list_t *nsiodlist;
};


