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
static struct tcpls_options *tcpls_o;

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
    ctx->support_tcpls_options = 1;
    ctx->random_bytes  = ptls_openssl_random_bytes;
    ctx->key_exchanges = ptls_openssl_key_exchanges;
    ctx->cipher_suites = ptls_openssl_cipher_suites;
done:
    return ctx;
}

int tcpls_get_addrs(unsigned int v4, unsigned int ours, char *optarg){
    int n = (v4==1) ? 15 : 40;
    unsigned int *m;
    char *addr;
    if(tcpls_o==NULL){
        tcpls_o = (struct tcpls_options*)malloc(sizeof(tcpls_o));
        memset(tcpls_o,0,sizeof(tcpls_o));
    }
    list_t *l = new_list(sizeof(char)*n, NB_ADDRESS_MAX);
    addr = (char*)malloc(sizeof(char)*ADDRESS_SIZE);
    addr = strtok(optarg, ",");
    if(addr == NULL)
        addr = optarg;
    switch((v4 << 1) | ours){
        case 0: 
            tcpls_o->peer_v6_addrs = l;
            tcpls_o->peer_v6 = 1;
            tcpls_o->nb_peer_v6_addrs = 0;
            m = &tcpls_o->nb_peer_v6_addrs;
            break;
        case 1:
            tcpls_o->ours_v6_addrs = l;
            tcpls_o->ours_v6 = 1;
            tcpls_o->nb_ours_v6_addrs = 0;
            m = &tcpls_o->nb_ours_v6_addrs;
            break;
        case 2:
            tcpls_o->peer_v4_addrs = l;
            tcpls_o->peer_v4 = 1;
            tcpls_o->nb_peer_v4_addrs = 0;
            m = &tcpls_o->nb_peer_v4_addrs;
            break;
        case 3:
            tcpls_o->ours_v4_addrs = l;
            tcpls_o->ours_v4 = 1;
            tcpls_o->nb_ours_v4_addrs = 0;
            m = &tcpls_o->nb_ours_v4_addrs;
            break;
        default:
            return -1;
    }
    if(addr==NULL){
        list_free(l);
        return -1;
    }
    while(addr!=NULL){
        if(*m >= NB_ADDRESS_MAX){
            fprintf(stderr, "Number of address should not "
                "exceed %d\n", NB_ADDRESS_MAX);
            list_free(l);
            return -1;
        }
        *m = *m + 1;
        list_add(l, addr);
        addr = strtok(NULL, ",");
    }
    return 0;
}

static int handle_addrs( unsigned int v4 , unsigned int ours){
    int i, n;
    list_t *l;
    struct sockaddr_in sockaddr;
    struct sockaddr_in6 sockaddr6;
    if(!tcpls || !tcpls_o)
        goto out;
    switch((v4 << 1) | ours){
        case 0: 
            n = tcpls_o->nb_peer_v6_addrs;
            l = tcpls_o->peer_v6_addrs;
            tcpls_o->peer_v6 = 0;
            break;
        case 1:
            n = tcpls_o->nb_ours_v6_addrs;
            l = tcpls_o->ours_v6_addrs;
            tcpls_o->ours_v6 = 0;
            break;
        case 2:
            n = tcpls_o->nb_peer_v4_addrs;
            l = tcpls_o->peer_v4_addrs;
            tcpls_o->peer_v4 = 0;
            break;
       case 3:
            n = tcpls_o->nb_ours_v4_addrs;
            l = tcpls_o->ours_v4_addrs;
            tcpls_o->ours_v4 = 0;
            break;
       default:
            return -1;
    }
    for(i = 0; i < n; i++){
        char *s = list_get(l, i);
        int primary = (i==0) ? 1 : 0;
        sockaddr.sin_port = htons(o.portno);
        if(v4){
            sockaddr.sin_family = AF_INET;
            if(inet_pton(AF_INET, s, &sockaddr.sin_addr)!=1){
                list_free(l);
                return -1;
            }
            if(tcpls_add_v4(tcpls->tls, &sockaddr, primary, ~ours, ours))
                return -1;	
        }
        else{
            if(inet_pton(AF_INET6, s, &sockaddr6.sin6_addr)!=1){
                list_free(l);
                return -1;
            }
            sockaddr6.sin6_family = AF_INET6;
            if(tcpls_add_v6(tcpls->tls, &sockaddr6, primary, ~ours, ours))
                return -1;
        }
    }
    return 0;
out:
    return -1;
}


static int tcpls_handle_options(void){
    int err;
    if(tcpls_o->ours_v6)
        if((err = handle_addrs(0, 1)))
            return -1;
    if(tcpls_o->ours_v4)
        if((err = handle_addrs(1, 1)))
            return -1;
    if(tcpls_o->peer_v6)
        if((err = handle_addrs(0, 0)))
            return -1;
    if(tcpls_o->peer_v4)
        if((err = handle_addrs(1, 0)))
            return -1;
    return 0;
}
