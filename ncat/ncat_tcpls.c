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
    if(tcpls_o==NULL){
        tcpls_o = (struct tcpls_options*)safe_zalloc(sizeof(tcpls_o));
        init_tcpls_options();
        peers_list = new_list(15,15);
        ours_list = new_list(15,15);
        peers6_list = new_list(40,15);
        ours6_list = new_list(40,15);
        nb_ours = 0; nb_peers = 0; nb_ours6 = 0; nb_peers6 = 0;
    }
    s = strtok(optarg, ",");
    while(s!=NULL){
        if(ours){
            if(af == AF_INET){
                list_add(ours_list, s);
                nb_ours++;
            }    
            else{
                list_add(ours6_list, s);
                nb_ours6++;
            }
        }
        else{
            if(af == AF_INET){
                list_add(peers_list, s);
                nb_peers++;
               
            }
            else{
                list_add(peers6_list, s);
                nb_peers6++;
            }
        }         
        s = strtok(NULL, ",");            
    }
    return 0;
}

static int tcpls_resolve_addrs(int is_server){
    union sockaddr_u addr;
    size_t sslen;
    int ret, i;
    int port;
    for(i = 0; i < nb_peers; i++){
        char *s = list_get(peers_list, i);
        ret = resolve(s, o.portno, &addr.storage, &sslen, AF_INET);
        if(ret!=0) return -1;
        peer_addrs[tcpls_o->nb_peers++] = addr;
    }
    
    for(i = 0; i < nb_peers6; i++){
        char *s = list_get(peers6_list, i);
        ret = resolve(s, o.portno, &addr.storage, &sslen, AF_INET6);
        if(ret!=0) return -1;
        peer_addrs[tcpls_o->nb_peers++] = addr;
    }
    for(i = 0; i < nb_ours; i++){
        char *s = list_get(ours_list, i);
        port = is_server ? o.portno : -1*(i+1) ;
        ret = resolve(s, port, &addr.storage, &sslen, AF_INET);
        if(ret!=0) return -1;
        ours_addrs[tcpls_o->nb_ours++] = addr;
    }
    
    for(i = 0; i < nb_ours6; i++){
        char *s = list_get(ours6_list, i);
        port = is_server ? o.portno : -1*(i+1) ;
        ret = resolve(s, port, &addr.storage, &sslen, AF_INET6);
        if(ret!=0) return -1;
        ours_addrs[tcpls_o->nb_ours++] = addr;
    }
    return 0;
}

int tcpls_add_addrs(unsigned int is_server){
    int i;
    tcpls = (tcpls_t *)tcpls_new(ctx,  is_server);
    if(tcpls_resolve_addrs(is_server)!=0)
       return(-1);
    int settopeer = tcpls->tls->is_server;
    for(i = 0; i < tcpls_o->nb_peers; i++){
        if(peer_addrs[i].storage.ss_family == AF_INET)
            tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&peer_addrs[i], 0, 0, 0);
        if(peer_addrs[i].storage.ss_family == AF_INET6)
            tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)&peer_addrs[i], 0, 0, 0);
    }
    for(i = 0; i < tcpls_o->nb_ours; i++){
        if(ours_addrs[i].storage.ss_family == AF_INET)
            tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&ours_addrs[i], 0, settopeer, 1);
        if(ours_addrs[i].storage.ss_family == AF_INET6)
            tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)&ours_addrs[i], 0, settopeer, 1);
    }
    return 0;
}

static nsock_iod tcpls_new_iod(nsock_pool nsp, int sd, struct sockaddr_storage *v4, size_t ssv4,
                              struct sockaddr_storage *v6, size_t ssv6 ){
    nsock_iod nsi = nsock_iod_new2(nsp, sd, NULL);
    if(nsi == NULL)
        return NULL;
    if(v4 != NULL)
        nsock_iod_set_localaddr(nsi, v4, ssv4);
    if(v6 != NULL)
        nsock_iod_set_localaddr(nsi, v6, ssv6);
    return nsi;
}

int do_tcpls_connect(nsock_pool nsp, nsock_iod nsiod, nsock_ev_handler handler){
    struct timeval timeout;
    ctx->output_decrypted_tcpls_data = 0;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    connect_info_t *con;
    nsock_iod nsi;
    int i, err = tcpls_connect(tcpls->tls, NULL, NULL, &timeout);
    if (err){
        fprintf(stderr, "tcpls_connect failed with err %d", err);
        return 1;
    }
    for(i = 0; i < tcpls->connect_infos->size; i++){
        con = list_get(tcpls->connect_infos, i);
        struct sockaddr_storage *src = (con->src == NULL) ? NULL : (struct sockaddr_storage *) &con->src->addr;
        struct sockaddr_storage *src6 = (con->src == NULL) ? NULL : (struct sockaddr_storage *) &con->src6->addr;
        if(!con->is_primary)
            nsi = tcpls_new_iod(nsp, con->socket, src, sizeof(src), src6, sizeof(src6));
        else {
            nsi = nsiod;
            if(src) nsock_iod_set_localaddr(nsi, src, sizeof(src));
            if(src6) nsock_iod_set_localaddr(nsi, src6, sizeof(src6));
            nsock_iod_tcpls_new(nsi, con->socket);
        }
        nsock_connect_tcpls(nsp, nsi, handler, 5, NULL);
    }
    return 0;
}

int do_tcpls_bind(fd_list_t *client_fdlist, fd_set *master_readfds, fd_set *listen_fds){
    int one = 1, i;
    size_t sslen = 0;
    init_fdlist(client_fdlist, sadd(o.conn_limit, tcpls_o->nb_ours + 1));
    for(i = 0; i < tcpls_o->nb_ours; i++){
        if(ours_addrs[i].storage.ss_family == AF_INET){
            if ((listenfd[i] = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
                perror("socket(2) failed");
                return -1;
            }
            sslen = sizeof(struct sockaddr_in);
        }
        if(ours_addrs[i].storage.ss_family == AF_INET6){
            if ((listenfd[i] = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
                perror("socket(2) failed");
                return -1;
            }
            sslen = sizeof(struct sockaddr_in6);
        }
        
        if (setsockopt(listenfd[i], SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0) {
           perror("setsockopt(SO_REUSEADDR) failed");
           return -1;
        }
        
        if (bind(listenfd[i], (struct sockaddr*) &ours_addrs[i], sslen) != 0) {
            perror("bind(2) failed");
            return -1;
        }
    
        if (listen(listenfd[i], SOMAXCONN) != 0) {
            perror("listen(2) failed");
            return -1;
        }
        unblock_socket(listenfd[i]);
        FD_SET(listenfd[i], master_readfds);
        add_fd(client_fdlist, listenfd[i]);
        FD_SET(listenfd[i], listen_fds);
    }
    return 0;
}


ptls_context_t *set_tcpls_ctx_options(void){
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
