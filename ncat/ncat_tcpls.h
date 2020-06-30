#include "picotls.h"
#include "picotls/openssl.h"
#include "containers.h"

#define NB_ADDRESS_MAX    15
#define ADDRESS_SIZE      15
#define V6_ADDRESS_SIZE   40

ptls_context_t *setup_tcpls_listen(void);
int tcpls_get_addrs(unsigned int v4, unsigned int ours, char *optarg);

struct tcpls_options{
    int timeoutval;
    unsigned int second;
    list_t *peer_v4_addrs;
    list_t *peer_v6_addrs;
    list_t *ours_v4_addrs;
    list_t *ours_v6_addrs;
    unsigned int nb_peer_v4_addrs;
    unsigned int nb_peer_v6_addrs;
    unsigned int nb_ours_v4_addrs;
    unsigned int nb_ours_v6_addrs;
    unsigned int timeout:1;
    unsigned int peer_v4:1;
    unsigned int ours_v4:1;
    unsigned int ours_v6:1;
    unsigned int peer_v6:1;
};
