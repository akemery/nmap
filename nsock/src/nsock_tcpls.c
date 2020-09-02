#include <openssl/pem.h>
#include <openssl/engine.h>

#include "picotls.h"
#include "picotls/openssl.h"
#include "containers.h"

#include "nsock.h"
#include "nsock_internal.h"
#include "nsock_ssl.h"

#if HAVE_PICOTCPLS

static int total_bytes_sent = 0;
static int has_migrated = 0;

static ptls_context_t *ptls_ctx_new(void){
  ptls_context_t *ptls_ctx;
  ptls_ctx = (ptls_context_t *) malloc (sizeof(ptls_ctx));   
  return(ptls_ctx);
}

void ptls_ctx_free(ptls_context_t *ptls_ctx){
  free(ptls_ctx);
}


static ptls_context_t *tcpls_init_helper(void) {
  ptls_context_t *ptls_ctx;
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  ptls_ctx = ptls_ctx_new();
  if (!ptls_ctx) {
    fatal("PICOTLS failed to create a new ptls_context_t: %s",
          ERR_error_string(ERR_get_error(), NULL));
  }
  return ptls_ctx;
}

static ptls_context_t *tcpls_init_common() {
  return tcpls_init_helper();
}

static nsock_ssl_ctx nsock_pool_tcpls_init_helper(struct npool *ms, int flags) {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  ms->ptlsctx->support_tcpls_options = 1;
  ms->ptlsctx->random_bytes = ptls_openssl_random_bytes;
  ms->ptlsctx->key_exchanges = ptls_openssl_key_exchanges;
  ms->ptlsctx->cipher_suites = ptls_openssl_cipher_suites;
  ms->ptlsctx->get_time = &ptls_get_time;
  ms->ptlsctx->update_open_count = NULL;
  return ms->ptlsctx;
}

nsock_ssl_ctx nsock_pool_tcpls_init(nsock_pool ms_pool, int flags) {
  struct npool *ms = (struct npool *)ms_pool;

  if (ms->ptlsctx == NULL)
    ms->ptlsctx = tcpls_init_common();
  return nsock_pool_tcpls_init_helper(ms, flags);
}

void nsock_iod_tcpls_new(nsock_iod nsi, int sd, tcpls_t *tcpls, int is_primary){
  nsi->sd = sd;
  nsi->tcpls_use_for_handshake = is_primary;
  nsi->tcpls = tcpls;
}

void nsock_iod_set_ctx(nsock_pool nsp, ptls_context_t *ctx){
    nsp->ptlsctx = ctx;
}

nsock_iod nsock_tcpls_connexion_migration(nsock_iod iod, int bytes_sent){
    struct niod *nsi = NULL;
    gh_lnode_t *current, *next;
    connect_info_t *con = NULL;
    int transportid = -1;
    ptls_handshake_properties_t prop = {NULL};
    int socket = -1;
    total_bytes_sent += bytes_sent;
    if(total_bytes_sent >= 5242880 && !has_migrated ){
        for (int i = 0; i < iod->tcpls->connect_infos->size; i++) {
            con = list_get(iod->tcpls->connect_infos, i);
            if (con->dest6) {
                socket = con->socket;
                transportid = con->this_transportid;
                break;
            }
        }
        for (current = gh_list_first_elem(&iod->nsp->active_iods); current != NULL; current = next) {
            next = gh_lnode_next(current);
            nsi = container_of(current, struct niod, nodeq);
            if(nsi->sd == socket)
                break;
        }
        assert(transportid != -1);
        assert(socket != -1 );
        prop.socket = socket;
        prop.client.transportid = transportid;
        prop.client.mpjoin = 1;
        int ret = tcpls_handshake(iod->tcpls->tls, &prop);
        if(ret){
            fprintf(stderr, "Error when sending handshake mpjoin (%d)\n", ret);
            return NULL;
        }
        has_migrated = 1;
    }
    
    return nsi;
}

int nsock_tcpls_connexion_migration_evt(nsock_iod iod, int bytes_sent){
    total_bytes_sent += bytes_sent;
    if(total_bytes_sent >= 5242880 && !has_migrated ){
        iod->enable_migration = 1;
        fprintf(stderr, "Total bytes sent %d\n", total_bytes_sent);       
    }
    return 0;
}


void nsock_check_sd(nsock_iod iod){
    fprintf(stderr, "Socket descriptor (%d)\n", iod->sd);
    return;
}

int tcpls_nsock_remove_nsiod(nsock_iod nsiod, int socket){
    gh_lnode_t *current, *next;
    struct niod *nsi;
    for (current = gh_list_first_elem(&nsiod->nsp->active_iods);
        current != NULL;
        current = next) {
        next = gh_lnode_next(current);
        nsi = container_of(current, struct niod, nodeq);
        if(nsi->sd == nsiod->sd){
            nsock_iod_delete(nsi, NSOCK_PENDING_ERROR);
            gh_list_remove(&nsiod->nsp->active_iods, current);
            gh_list_prepend(&nsiod->nsp->free_iods, &nsi->nodeq);
            break;
        }
    }
    fprintf(stderr, "Remove NSIOD with socket descriptor (%d)\n", socket);
    return 0;
}

int nsock_tcpls_cmp_sd(nsock_iod nsiod, int socket){
    return(nsiod->sd == socket);
}

nsock_iod nsock_tcpls_check_migration(nsock_iod iod){
    struct niod *nsi = NULL;
    gh_lnode_t *current, *next;
    connect_info_t *con = NULL;
    int socket =  0, ret = 0;
    if(iod->enable_migration){
        for (int i = 0; i < iod->tcpls->connect_infos->size; i++) {
            con = list_get(iod->tcpls->connect_infos, i);
            if (con->dest6) {
                socket = con->socket;
                break;
            }
        }
        for (current = gh_list_first_elem(&iod->nsp->active_iods); current != NULL; current = next) {
            next = gh_lnode_next(current);
            nsi = container_of(current, struct niod, nodeq);
            if(nsi->sd == socket)
                break;
        }
        streamid_t streamid = tcpls_stream_new(iod->tcpls->tls, NULL, (struct sockaddr*) &iod->tcpls->v6_addr_llist->addr);
        ret = tcpls_streams_attach(iod->tcpls->tls, streamid, 1);
        tcpls_stream_t *old_stream = list_get(iod->tcpls->streams, 0);
        assert(old_stream); 
        ret = tcpls_stream_close(iod->tcpls->tls, old_stream->streamid, 1); 
        fprintf(stderr, "--- send stream close: (%d) (%d) (%d) (%d) (%ld) (%ld)----\n", iod->sd, streamid, iod->tcpls->streams->size, ret, sizeof(struct niod), sizeof(nsock_iod));
    }
    return nsi;
}

void nsock_tcpls_set_migration(nsock_iod nsi){
    nsi->migration = 1;
}

int nsock_tcpls_engine_iod_unregister(nsock_iod nsiod){
   assert(nsiod->nsp);
   return nsock_engine_iod_unregister(nsiod->nsp, nsiod);
}

size_t  nsock_get_iod_size(void){
    return sizeof(struct niod);
}
#endif
