#include <string.h>
#include <stdio.h>
#include <openssl/pem.h>
#include <openssl/engine.h>


#include "nbase.h"
#include "ncat_config.h"

#include "nsock.h"
#include "ncat.h"

#include "picotls.h"
#include "picotls/openssl.h"
#include "containers.h"


static ptls_context_t *ctx;
static tcpls_t *tcpls;

static void tcpls_init(unsigned int is_server){
  FILE *fp;
  memset(&ctx,0,sizeof(ctx));
  ctx->random_bytes = ptls_openssl_random_bytes;
  ctx->key_exchanges = ptls_openssl_key_exchanges;
  ctx->cipher_suites = ptls_openssl_cipher_suites;
  if(!is_server){
    ptls_openssl_verify_certificate_t verifier;
    ptls_openssl_init_verify_certificate(&verifier, NULL);
    ctx->verify_certificate = &verifier.super;
  }else{
    static ptls_iovec_t certs[16];
    size_t count = 0;
    fp = fopen("cert-chain.pem", "rb");
    assert(fp!=NULL);
    X509 *cert;
    while((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL){
      ptls_iovec_t *dst = certs + count++;
      dst->len = i2d_X509(cert,&dst->base);
    }
    fclose(fp);
    ctx->certificates.list = certs;
    ctx->certificates.count = count;
   }
   static ptls_openssl_sign_certificate_t signer;
   fp = fopen("optarg", "rb");
   assert(fp!=NULL);
   EVP_PKEY *pkey = PEM_read_PrivateKey(fp,NULL,NULL,NULL);
   assert(pkey != NULL);
   ptls_openssl_init_sign_certificate(&signer,pkey);
   EVP_PKEY_free(pkey);
   ctx->sign_certificate = &signer.super;
   fclose(fp);
   ctx->support_tcpls_options = 1;
   tcpls = tcpls_new(&ctx,is_server);
}
#if 0
int tcpls_handshake(ptls *tls, ptls_hand){
  return tcpls_hanshake(ptls, properties);
}
#endif


static int load_private_key(ptls_context_t *ctx, const char *fn){
    static ptls_openssl_sign_certificate_t sc;
    FILE *fp;
    EVP_PKEY *pkey;
    if ((fp = fopen(fn, "rb")) == NULL) {
        fprintf(stderr, "failed to open file:%s:%s\n", fn, strerror(errno));
        return(-1);
    }
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL) {
        fprintf(stderr, "failed to read private key from file:%s\n", fn);
        return(-1);
    }
    ptls_openssl_init_sign_certificate(&sc, pkey);
    EVP_PKEY_free(pkey);
    ctx->sign_certificate = &sc.super;
    return(0);
}

ptls_context_t *setup_tcpls_listen(void){
    if(ctx)
        goto done;
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    ctx = (ptls_context_t *)malloc(sizeof(ctx));
    memset(ctx,0,sizeof(ctx));
    if (ptls_load_certificates(ctx, (char *)o.tcplscert) != 0)
        bye("failed to load certificate:%s:%s\n", o.tcplscert, strerror(errno));
    printf("%s %s\n", o.tcplscert, o.tcplskey);
    if(load_private_key(ctx, (char*)o.tcplskey) != 0)
        bye("failed to load key:%s:%s\n", o.tcplskey, strerror(errno));
    ctx.support_tcpls_options = 1;
done:
    return ctx;
}


