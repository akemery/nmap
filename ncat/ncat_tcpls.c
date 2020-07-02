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
struct tcpls_options *tcpls_o;

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


ptls_context_t *setup_tcpls_ctx(void){
    if(ctx)
        goto done;
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    ctx = (ptls_context_t *)malloc(sizeof(ctx));
    if(o.tcplscert){
        if (ptls_load_certificates(ctx, (char *)o.tcplscert) != 0)
            bye("failed to load certificate:%s:%s\n", o.tcplscert, strerror(errno));
    }
    if(o.tcplskey){
        if(load_private_key(ctx, (char*)o.tcplskey) != 0)
            bye("failed to load key:%s:%s\n", o.tcplskey, strerror(errno));
    }
    ctx->support_tcpls_options = 1;
    ctx->random_bytes = ptls_openssl_random_bytes;
    ctx->key_exchanges = ptls_openssl_key_exchanges;
    ctx->cipher_suites = ptls_openssl_cipher_suites;
    ctx->get_time = &ptls_get_time;
    ctx->update_open_count = NULL;
done:
    return ctx;
}


static void init_tcpls_options(void){
    tcpls_o->timeoutval = -1;
    tcpls_o->second = -1;
    tcpls_o->nb_peers = 0;
    tcpls_o->nb_ours = 0;
    return;
};



int tcpls_get_addrsv2(int af, unsigned int ours, char *optarg){
    char *s;
    union sockaddr_u add;
    size_t sslen;
    int rc;
    if(tcpls_o==NULL){
        tcpls_o = (struct tcpls_options*)safe_zalloc(sizeof(tcpls_o));
        init_tcpls_options();
    }
    s = strtok(optarg, ",");
    while(s!=NULL){
       // addr2= strdup(addr);
        rc = resolve(s, o.portno, &add.storage, &sslen, af);
        if(rc!=0) return -1;
        if(ours)
            ours_addrs[tcpls_o->nb_ours++] = add;
        else
            peer_addrs[tcpls_o->nb_peers++] = add;         
        s = strtok(NULL, ",");            
    }
    return 0;
}

int tcpls_add_addrs(unsigned int is_server){
    int i;
    tcpls = (tcpls_t *)tcpls_new(ctx,  is_server);
    for(i = 0; i < tcpls_o->nb_peers; i++){
        if(peer_addrs[i].storage.ss_family == AF_INET)
            tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&peer_addrs[i], 0, 0, 0);
        if(peer_addrs[i].storage.ss_family == AF_INET6)
            tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)&peer_addrs[i], 0, 0, 0);
    }
    for(i = 0; i < tcpls_o->nb_ours; i++){
        if(ours_addrs[i].storage.ss_family == AF_INET)
            tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&ours_addrs[i], 0, 0, 0);
        if(ours_addrs[i].storage.ss_family == AF_INET6)
            tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)&ours_addrs[i], 0, 0, 0);
    }
    return 0;
}

int do_tcpls_connect(void){
    struct timeval timeout;
    ctx->output_decrypted_tcpls_data = 0;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    int err = tcpls_connect(tcpls->tls, NULL, NULL, &timeout);
    if (err){
        fprintf(stderr, "tcpls_connect failed with err %d", err);
        return 1;
    }
    return 0;
}

int do_tcpls_bind(void){
    int one = 1, i;
    size_t sslen;
    for(i = 0; i < tcpls_o->nb_ours; i++){
        if(ours_addrs[i].storage.ss_family == AF_INET){
            if ((listenfd[i] = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                perror("socket(2) failed");
                return 1;
            }
            sslen = sizeof(struct sockaddr_in);
        }
        if(ours_addrs[i].storage.ss_family == AF_INET6){
            if ((listenfd[i] = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
                perror("socket(2) failed");
                return 1;
            }
            sslen = sizeof(struct sockaddr_in6);
        }
        if (setsockopt(listenfd[i], SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
           perror("setsockopt(SO_REUSEADDR) failed");
           return 1;
        }
        
        if (bind(listenfd[i], (struct sockaddr*) &ours_addrs[i], sslen) != 0) {
            perror("bind(2) failed");
            return 1;
        }
    
        if (listen(listenfd[i], SOMAXCONN) != 0) {
            perror("listen(2) failed");
            return 1;
        }
    }
    return 0;
}
