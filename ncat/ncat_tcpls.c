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
#include "util1.h"

#include <arpa/inet.h>


static ptls_context_t *ctx;
static tcpls_t *tcpls;
static struct cli_data cli_data;
static struct conn_state *con_state;
static list_t *tcpls_con_l;

//static void printaddr(struct sockaddr_storage *src);
static int handle_mpjoin(int socket, uint8_t *connid, uint8_t *cookie, uint32_t transportid, void *cbdata) ;
static int handle_connection_event(tcpls_event_t event, int socket, int transportid, void *cbdata) ;
static int handle_stream_event(tcpls_t *tcpls, tcpls_event_t event,
    streamid_t streamid, int transportid, void *cbdata);
static int handle_client_connection_event(tcpls_event_t event, int socket, int transportid, void *cbdata) ;
static int handle_client_stream_event(tcpls_t *tcpls, tcpls_event_t event, streamid_t streamid,
    int transportid, void *cbdata);


/*static int load_private_key(ptls_context_t *ctx, const char *fn){
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
}*/

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
    fprintf(stderr, "port %d\n", o.portno);
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
        port = is_server ? o.portno : -1*(i+3) ;
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

int do_init_tcpls(int is_server){
    tcpls = (tcpls_t *)tcpls_new(ctx,  is_server);
    if(is_server)
        tcpls_con_l = new_list(sizeof(struct tcpls_con),tcpls_o->nb_ours);
    if(tcpls_resolve_addrs(is_server)!=0)
       return(-1);
    return 0;
}

static int tcpls_add_addrs(unsigned int is_server, tcpls_t * tcpls){
    int i;
    int settopeer = tcpls->tls->is_server;
    for(i = 0; i < tcpls_o->nb_peers; i++){
        if(peer_addrs[i].storage.ss_family == AF_INET){
            tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&peer_addrs[i], 0, 0, 0);
        }
        if(peer_addrs[i].storage.ss_family == AF_INET6){
            tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)&peer_addrs[i], 0, 0, 0);
        }
    }
    for(i = 0; i < tcpls_o->nb_ours; i++){
        if(ours_addrs[i].storage.ss_family == AF_INET){
            tcpls_add_v4(tcpls->tls, (struct sockaddr_in*)&ours_addrs[i], 0, settopeer, 1);
        }
        if(ours_addrs[i].storage.ss_family == AF_INET6){
            tcpls_add_v6(tcpls->tls, (struct sockaddr_in6*)&ours_addrs[i], 0, settopeer, 1);
        }
    }
    return 0;
}

int do_tcpls_add_addrs(unsigned int is_server, tcpls_t * ctcpls){
    if(ctcpls == NULL)
        return tcpls_add_addrs(is_server, tcpls);
    else
        return tcpls_add_addrs(is_server, ctcpls);
}


static nsock_iod tcpls_new_iod(nsock_pool nsp, int sd, struct sockaddr_storage *v4, size_t ssv4,
                              struct sockaddr_storage *v6, size_t ssv6 , tcpls_t *tcpls){
    nsock_iod nsi = nsock_iod_new2(nsp, sd, NULL);
    if(nsi == NULL)
        return NULL;
    if(v4 != NULL)
        nsock_iod_set_localaddr(nsi, v4, ssv4);
    if(v6 != NULL)
        nsock_iod_set_localaddr(nsi, v6, ssv6);
    nsock_iod_tcpls_new(nsi,sd, tcpls, 0);
    return nsi;
}

/*static void printaddr(struct sockaddr_storage *src ){
   char buf[INET6_ADDRSTRLEN +1];
   inet_ntop(src->ss_family, src, buf, sizeof(buf));
   printf("addr: %s\n", buf);           
}*/

int do_tcpls_connect(nsock_pool nsp, nsock_iod nsiod, nsock_ev_handler handler, struct conn_state *cs){
    struct timeval timeout;
    ctx->output_decrypted_tcpls_data = 0;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    connect_info_t *con;
    nsock_iod nsi = NULL;
    int i, err = tcpls_connect(tcpls->tls, NULL, NULL, &timeout);
    if (err){
        fprintf(stderr, "tcpls_connect failed with err %d", err);
        return 1;
    }
    nsock_iod_set_ctx(nsp, ctx);
    con_state = cs;
    assert(con_state->sock_nsi == nsiod);
    for(i = 0; i < tcpls->connect_infos->size; i++){
        con = list_get(tcpls->connect_infos, i);
        struct sockaddr_storage *src = (con->src == NULL) ? NULL : (struct sockaddr_storage *) &con->src->addr;
        struct sockaddr_storage *src6 = (con->src6 == NULL) ? NULL : (struct sockaddr_storage *) &con->src6->addr;
        if(!con->is_primary)
            nsi = tcpls_new_iod(nsp, con->socket, src, sizeof(*src), src6, sizeof(*src6), tcpls);
        else {
            nsi = nsiod;
            if(src) nsock_iod_set_localaddr(nsi, src, sizeof(*src));
            if(src6) nsock_iod_set_localaddr(nsi, src6, sizeof(*src6));
            nsock_iod_tcpls_new(nsi, con->socket, tcpls, 1);
        }
        list_add(cli_data.nsiodlist, nsi);
        if(o.connexion_migration)
            nsock_tcpls_set_migration(nsi);
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
        FD_SET(listenfd[i], listen_fds);
        add_fd(client_fdlist, listenfd[i]);
    }
    return 0;
}


ptls_context_t *set_tcpls_ctx_options(int is_server){
    if(ctx)
        goto done;
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    ctx = (ptls_context_t *)malloc(sizeof(*ctx));
    memset(ctx, 0, sizeof(ptls_context_t));
    if(o.tcplscert){
        if (ptls_load_certificates(ctx, (char *)o.tcplscert) != 0)
            bye("failed to load certificate:%s:%s\n", o.tcplscert, strerror(errno));
    }
    if(o.tcplskey){
        load_private_key(ctx, (char*)o.tcplskey);
    }
    ctx->support_tcpls_options = 1;
    ctx->random_bytes = ptls_openssl_random_bytes;
    ctx->key_exchanges = ptls_openssl_key_exchanges;
    ctx->cipher_suites = ptls_openssl_cipher_suites;
    ctx->get_time = &ptls_get_time;
    if(!is_server){
        ctx->send_change_cipher_spec = 1;
        list_t *socklist = new_list(sizeof(int), 2);
        list_t *streamlist = new_list(sizeof(tcpls_stream_t), 2);
        list_t *nsiodlist   = new_list(nsock_get_iod_size(), 2);
        cli_data.socklist = socklist;
        cli_data.streamlist = streamlist;
        cli_data.nsiodlist = nsiodlist;
        ctx->cb_data = &cli_data;
        ctx->stream_event_cb = &handle_client_stream_event;
        ctx->connection_event_cb = &handle_client_connection_event;
    }
    else
        setup_session_cache(ctx);  
done:
    return ctx;
}

static int handle_connection_event(tcpls_event_t event, int socket, int transportid, void *cbdata) {
    list_t *conntcpls = (list_t*) cbdata;
    struct tcpls_con *con;
    assert(conntcpls);
    switch(event){
        case CONN_OPENED:
            fprintf(stderr, "CONN OPENED %d:%d:%d\n", socket, event, transportid);
            for (int i = 0; i < conntcpls->size; i++) {
                con = list_get(conntcpls, i);
                if (con->sd == socket) {
                    con->transportid = transportid;
                    break;
                 }
            }
            break;
        case CONN_CLOSED:
            fprintf(stderr, "CONN CLOSED %d:%d\n",socket, event);
            for (int i = 0; i < conntcpls->size; i++) {
                con = list_get(conntcpls, i);
                if (con->sd == socket) {
                    list_remove(conntcpls, con);
                    break;
                }
            }
            break;
        default:
            break;
    }
    return 0;
}


static int handle_client_connection_event(tcpls_event_t event, int socket, int transportid, void *cbdata) {
    struct cli_data *data = (struct cli_data*) cbdata;
    switch (event) {
        case CONN_CLOSED:
            fprintf(stderr, "Received a CONN_CLOSED; removing the socket (%d)\n", socket);
            list_remove(data->socklist, &socket);
            for(int i = 0; i < data->nsiodlist->size; i++){
                nsock_iod nsiod =  list_get(data->nsiodlist, i);
                if(nsock_tcpls_cmp_sd(nsiod, socket)){
                    assert(nsiod);
                    tcpls_nsock_remove_nsiod(nsiod, socket);
                }
            }
            break;
        case CONN_OPENED:
            fprintf(stderr, "Received a CONN_OPENED; adding the socket %d\n", socket);
            list_add(data->socklist, &socket);
            break;
        default: break;
    }
    return 0;
}
    
static int handle_client_stream_event(tcpls_t *tcpls, tcpls_event_t event, streamid_t streamid,
    int transportid, void *cbdata) {
  struct cli_data *data = (struct cli_data*) cbdata;
  switch (event) {
    case STREAM_OPENED:
      fprintf(stderr, "Handling stream_opened callback\n");
      list_add(data->streamlist, &streamid);
      break;
    case STREAM_CLOSED:
      fprintf(stderr, "Handling stream_closed callback\n");
      list_remove(data->streamlist, &streamid);
      break;
    default: break;
  }
  return 0;
}

static int handle_stream_event(tcpls_t *tcpls, tcpls_event_t event,
    streamid_t streamid, int transportid, void *cbdata) {
    list_t *conntcpls = (list_t*) cbdata;
    struct tcpls_con *con;
    assert(conntcpls);
    switch(event){
        case STREAM_OPENED:
            fprintf(stderr, "STREAM OPENED %d %d %d (%d)\n", streamid, event, transportid, tcpls->streams->size);
            for (int i = 0; i < conntcpls->size; i++) {
                con = list_get(conntcpls, i);
                if (con->tcpls == tcpls && con->transportid == transportid) {
                    fprintf(stderr, "Setting streamid %u as wants to write %d %d\n", streamid, transportid, con->sd);
                    con->streamid = streamid;
                    con->is_primary = 1;
                    con->wants_to_write = 1;
                    con->fdi->wants_to_write = 1;
                }
            }
            break;
        case STREAM_CLOSED:
            fprintf(stderr, "STREAM CLOSED %d %d %d\n", streamid, event, transportid);
            for (int i = 0; i < conntcpls->size; i++) {
                con = list_get(conntcpls, i);
                if ( con->tcpls == tcpls && con->transportid == transportid) {
                    fprintf(stderr, "We're stopping to write on the connection linked to transportid %d %d\n", transportid, con->sd);
                    con->is_primary = 0;
                    con->wants_to_write = 0;
                    con->fdi->wants_to_write = 0;
                }
            }
            break;
        default:
            break;
    }
    return 0;
}

int do_tcpls_accept(int socket, struct sockaddr *sockaddr, socklen_t  *sslen, int *is_primary, struct fdinfo *fdi){
    int cfd = accept(socket, sockaddr, sslen);
    if(cfd < 0) return cfd;
    fprintf(stderr, "Accepting a new connection %d\n", cfd);
    struct tcpls_con *con = (struct tcpls_con *)malloc(sizeof(*con));
    ctx->cb_data = tcpls_con_l;
    ctx->connection_event_cb = &handle_connection_event;
    ctx->stream_event_cb = &handle_stream_event;
    tcpls_t *new_tcpls = tcpls_new(ctx,  1);
    tcpls_add_addrs(1, new_tcpls);
    con->sd = cfd;
    con->tcpls = new_tcpls;
    assert(con->tcpls->tls->is_server);
    list_add(tcpls_con_l, con);
    tcpls_add_addrs(1, new_tcpls);
    if (tcpls_accept(new_tcpls, cfd, NULL, 0) < 0)
        fprintf(stderr, "tcpls_accept returned -1");
    fdi->tcpls = new_tcpls;
    fdi->wants_to_write = 0;
    return cfd;
}

static int handle_mpjoin(int socket, uint8_t *connid, uint8_t *cookie, uint32_t transportid, void *cbdata) {
    int i, j;
    fprintf(stderr, "\n\n\nstart mpjoin haha %d %d %d %d %p\n", socket, *connid, *cookie, transportid, cbdata);
    list_t *conntcpls = (list_t*) cbdata;
    struct tcpls_con *con, *con2;
    assert(conntcpls);
    for(i = 0; i<conntcpls->size; i++){
        con = list_get(conntcpls, i);
        if(!memcmp(con->tcpls->connid, connid, CONNID)){
            for(j = 0; j < conntcpls->size; j++){
                con2 = list_get(conntcpls, j);
                if(con2->sd == socket)
                    con2->tcpls = con->tcpls; 
            }
            return tcpls_accept(con->tcpls, socket, cookie, transportid);
        }
    }
    return -1;
}

int do_tcpls_handshake(struct fdinfo *fdi){
    int i, ret = -1, found = 0;
    struct tcpls_con *con = NULL;
    for(i = 0; i < tcpls_con_l->size ; i++){
        con = list_get(tcpls_con_l, i);
        if(con->sd == fdi->fd){
            found = 1 ;
            break;
        }
    }
    ptls_handshake_properties_t prop = {NULL};
    memset(&prop, 0, sizeof(prop));
    prop.socket = fdi->fd;
    prop.received_mpjoin_to_process = &handle_mpjoin;
    if ((ret = tcpls_handshake(con->tcpls->tls, &prop)) != 0) {
        if (ret == PTLS_ERROR_HANDSHAKE_IS_MPJOIN) {
            if(found && con->tcpls){
                fdi->tcpls = con->tcpls;
                con->fdi = fdi;
            }
            return ret;
        }
        fprintf(stderr, "tcpls_handshake failed with ret (%d)\n", ret);
    }
    con->fdi = fdi;
    fdi->tcpls = con->tcpls;
    return ret;
}


size_t tcpls_write(int cfd, struct fdinfo *fdi){
    static const size_t block_size = 8192;
    uint8_t buf[block_size];
    int ret = -1, ioret = -1 ,i, found = 0;
    struct tcpls_con *con;
    int streamid;
    if(fdi->wants_to_write && fdi->tcpls){
        while ((ioret = read(o.inputfd, buf, block_size)) == -1 && errno == EINTR)
            ;
        if(ioret > 0){
            for(i = 0; i < tcpls_con_l->size ; i++){
                con = list_get(tcpls_con_l, i);
                if(con->sd == cfd){
                    found = 1;
                    break;
                }
            }
            if(found){
                if((ret = tcpls_send(fdi->tcpls->tls, con->streamid, buf, ioret)) < 0) {
                    fprintf(stderr, "tcpls_send returned %d\n for sending on streamid %u",
                       ret, streamid);
                    return -1;
                }  
            }
            return ret;
        } else if (ioret == 0) {
            fprintf(stderr, "End-of-file, closing the connection %d:%d:%d:%d\n", cfd, o.inputfd, ioret, errno);
            close(o.inputfd);
            return 0;
        }
    }
    return ioret;
}
