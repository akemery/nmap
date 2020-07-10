#include <openssl/pem.h>
#include <openssl/engine.h>

#include "picotls.h"
#include "picotls/openssl.h"
#include "containers.h"

#include "nsock.h"
#include "nsock_internal.h"
#include "nsock_ssl.h"

#if HAVE_PICOTCPLS

static ptls_context_t *ptls_ctx_new(void){
  ptls_context_t *ptls_ctx;
  ptls_ctx = (ptls_context_t *) malloc (sizeof(ptls_ctx));   
  return(ptls_ctx);
}

static void ptls_ctx_free(ptls_context_t *ptls_ctx){
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

void nsock_iod_tcpls_new(nsock_iod nsi, int sd){
  nsi->sd = dup(sd);
}
#endif
