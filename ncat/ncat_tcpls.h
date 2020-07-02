#include "picotls.h"
#include "picotls/openssl.h"
#include "containers.h"

#define NB_ADDRESS_MAX    15
#define ADDRESS_SIZE      15
#define V6_ADDRESS_SIZE   40

union sockaddr_u peer_addrs[NB_ADDRESS_MAX];
union sockaddr_u ours_addrs[NB_ADDRESS_MAX];
int listenfd[NB_ADDRESS_MAX];
    
ptls_context_t *setup_tcpls_ctx(void);
int tcpls_get_addrsv2(int af, unsigned int ours, char *optarg);
int tcpls_add_addrs(unsigned int is_server);
int do_tcpls_connect(void);
int do_tcpls_bind(void);


struct tcpls_options{
    int timeoutval;
    unsigned int second;
    unsigned int nb_peers;
    unsigned int nb_ours;
};
