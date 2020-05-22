/* Copyright 2020 Exein. All Rights Reserved.

Licensed under the GNU General Public License, Version 3.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.gnu.org/licenses/gpl-3.0.html

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/


//TODO: implement a fuction to free allocated resource for a deleted pid


//#define DEBUG
#define uthash_malloc(sz) mealloc(uhandle->hash_shm)

#include "include/libexnl.h"


static char version[] = VERSION_STRING;
static char timestamp[] __attribute__((used)) = __DATE__ " " __TIME__;

void (*exein_new_pid_notify_cb)(uint16_t)=NULL;
void (*exein_delete_pid_cb)(uint16_t)=NULL;

void * get_pc () { return __builtin_return_address(0); }

void exein_dummy_pid_notify_cb(uint16_t pid){
	printf("libexnl.dummy_pid_notify_cb - New pid (%d) have been observed.\n",pid);
}

void exein_dummy_pid_delete_cb(uint16_t pid){
        printf("libexnl.dummy_pid_delete_cb - pid (%d) have been deleted\n",pid);
}

void exein_print_version(){
	printf("%s\n",version);
}

int exein_remove_pid(exein_shandle *uhandle, uint16_t pid){

	exein_pids              *pid_data=NULL;

	DODEBUG("libexnl.exein_remove_pid - (%p,%d)\n", uhandle, pid);
	for(pid_data=uhandle->pids; pid_data != NULL; pid_data=(exein_pids *)(pid_data->hh.next)) {
		if (pid_data->pid==pid){
			DODEBUG("libexnl.exein_remove_pid - Requested %d found delete from hash and free memory.\n", pid);
			HASH_DEL(uhandle->pids, pid_data);
			munmap(pid_data, sizeof(exein_pids));
			return EXEIN_NOERR;
			}
		}
	DODEBUG("libexnl.exein_remove_pid - Requested %d *NOT* found.\n", pid);
	return EXEIN_ERR_NOPID;
}


int exein_fetch_data(exein_shandle *uhandle, uint16_t pid, uint16_t *dstbuf){
        exein_prot_req_t	data_req={
				.key            = uhandle->key,
				.message_id     = EXEIN_MSG_DATA_RQ,
				.tag            = uhandle->tag,
				.padding        = 0,
				.pid            = pid,
				};
	exein_pids		*pid_data=NULL;
	struct timespec 	ts;
	int			found=0, tmp;

	//find the semaphore on which wait
	DODEBUG("libexnl.exein_fetch_data - look for given pid=%d\n", pid);
	for(pid_data=uhandle->pids; pid_data != NULL; pid_data=(exein_pids *)(pid_data->hh.next)) {
		if (pid_data->pid==pid){
			DODEBUG("libexnl.exein_fetch_data - pid=%d FOUND\n", pid);
			found=1;
			break;
			}
		}
	//ask data
	DODEBUG("libexnl.exein_fetch_data - prepare netlink socket\n");
	memcpy( NLMSG_DATA(uhandle->nlh_sk), &data_req, EXEIN_PKT_SIZE); //EXEIN_PKT_SIZE constant
	uhandle->nlh_sk->nlmsg_pid=uhandle->cpid;

	//check what we got
	if (found==0){//need to initialize data structure
		DODEBUG("libexnl.exein_fetch_data - since pid has not be found, needs to allocate new ringbuffer before request data\n");
		if (!(pid_data=(exein_pids *) mealloc( RESERVED2BASE(uhandle) ))){
			DODEBUG("libexnl.exein_fetch_data - can't allocate mem 4 data, quit!\n");
			uhandle->trouble=EXEIN_STAT_RF_ENOMEM;
			return EXEIN_ERR_NOMEM;
			}
		DODEBUG("libexnl.exein_fetch_data - salloc returned pointer for pid_data=%p\n", pid_data);
		pid_data->pid=pid;
		sem_init(&pid_data->semaphore, 1, 0);

		HASH_ADD(hh,uhandle->pids,pid,sizeof(uint16_t),pid_data);
		}

	DODEBUG("libexnl.exein_fetch_data - send netlink message uhandle=%p, uhandle->buffers_pool=%p\n", uhandle, uhandle->buffers_pool);

//	pid_data->buffer=dstbuf;
	pid_data->buffer=get_sbuff(uhandle->buffers_pool);
	DODEBUG("libexnl.exein_fetch_data - resquested buffer is @%p bufferpool structure is @%p\n", pid_data->buffer, uhandle->buffers_pool);
	if (sendmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) {
			DODEBUG("libexnl.exein_fetch_data - netlink message on fd=%d failed @sendmsg\n", uhandle->sock_fd);
			return EXEIN_ERR_NLCOM;
			}
//	DODEBUG("libexnl.exein_fetch_data - Wait the answer on semaphore\n");
#ifdef DEBUG
	sem_getvalue(&pid_data->semaphore, &tmp);
#endif
	DODEBUG("libexnl.exein_fetch_data - semaphore value before sem_wait is %d\n", tmp);
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		DODEBUG("libexnl.exein_fetch_data - Clock clock_gettime error!\n");
		return EXEIN_ERR_CLOCKFAILURE;
		}
	ts.tv_sec += EXEIN_FD_TIMEOUT_SEC;
	ts.tv_nsec += EXEIN_FD_TIMEOUT_NSEC;
	tmp = sem_timedwait(&pid_data->semaphore, &ts);
	if (tmp==-1) {
		tmp=EXEIN_ERR_TIMEOUT;
		} else {
			tmp=EXEIN_NOERR;
			}
	DODEBUG("libexnl.exein_fetch_data - data arrived, copy data on local buffer and return to caller\n");
	memcpy(dstbuf, pid_data->buffer, EXEIN_BUFFES_SIZE*sizeof(uint16_t)); //EXEIN_BUFFES_SIZE*sizeof(uint16_t) constant
	rel_sbuf(uhandle->buffers_pool, pid_data->buffer);
	return tmp;
}

static int netlink_setup(exein_shandle *uhandle, pid_t bind_pid){

	DODEBUG("libexnl.netlink_setup - prepare netlink stuffs\n");
	uhandle->sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
	if(uhandle->sock_fd<0) return EXEIN_ERR_NLSOCKET;
	memset(uhandle->src_addr, 0, sizeof(struct sockaddr_nl));
	uhandle->src_addr->nl_family = AF_NETLINK;
	uhandle->src_addr->nl_pid = bind_pid;
	if (bind(uhandle->sock_fd, (struct sockaddr *)uhandle->src_addr, sizeof(struct sockaddr_nl))<0) return EXEIN_ERR_NLBIND;
	memset(uhandle->dest_addr, 0, sizeof(struct sockaddr_nl));
	uhandle->dest_addr->nl_family = AF_NETLINK;
	uhandle->dest_addr->nl_pid = 0;
	uhandle->dest_addr->nl_groups = 0;
	return EXEIN_NOERR;
}

static int netlink_msg_init(int max_payload, pid_t bind_pid, exein_shandle *uhandle){

	DODEBUG("libexnl.netlink_msg_init - \n");
	uhandle->msg_sk->msg_iov= (struct iovec *) malloc(sizeof(struct iovec));
	if (!uhandle->msg_sk->msg_iov) return EXEIN_ERR_NOMEM;
	uhandle->msg_sk->msg_iov->iov_base = (struct nlmsghdr *)malloc(NLMSG_SPACE(max_payload));
	if (!uhandle->msg_sk->msg_iov->iov_base) return EXEIN_ERR_NOMEM;
	uhandle->nlh_sk = uhandle->msg_sk->msg_iov->iov_base;
	if (uhandle->msg_sk->msg_iov->iov_base){
		memset(uhandle->msg_sk->msg_iov->iov_base, 0, NLMSG_SPACE(max_payload));
		((struct nlmsghdr *) uhandle->msg_sk->msg_iov->iov_base)->nlmsg_len	= NLMSG_SPACE(max_payload);
		((struct nlmsghdr *) uhandle->msg_sk->msg_iov->iov_base)->nlmsg_pid	= bind_pid;
		((struct nlmsghdr *) uhandle->msg_sk->msg_iov->iov_base)->nlmsg_flags	= 0;
		uhandle->msg_sk->msg_iov->iov_len	= ((struct nlmsghdr *) uhandle->msg_sk->msg_iov->iov_base)->nlmsg_len;
		uhandle->msg_sk->msg_name		= (void *)uhandle->dest_addr;
		uhandle->msg_sk->msg_namelen	= sizeof(struct sockaddr_nl);
		uhandle->msg_sk->msg_iovlen	= 1;
		uhandle->msg_sk->msg_control	= NULL;
		uhandle->msg_sk->msg_controllen	= 0;
		uhandle->msg_sk->msg_flags		= 0;
		return EXEIN_NOERR;
		} else return EXEIN_ERR_NOMEM;
}

static int exein_nl_peer_register(exein_shandle *uhandle, exein_prot_req_t *rpacket){

	DODEBUG("libexnl.exein_nl_peer_register - send registration request\n");
	memcpy(NLMSG_DATA(uhandle->nlh_sk), rpacket, EXEIN_PKT_SIZE); //EXEIN_PKT_SIZE constant
	if (sendmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) return EXEIN_ERR_NLCOM;
	if (recvmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) return EXEIN_ERR_NLCOM;
	DODEBUG("libexnl.exein_nl_peer_register - received answer\n");
	if (strncmp((char *)NLMSG_DATA(uhandle->nlh_sk), "ACK", 3)!=0) return EXEIN_ERR_REGISTER;
	DODEBUG("libexnl.exein_nl_peer_register - answer ok\n");
	return EXEIN_NOERR;
}

static void stack_trace(){
	void *trace[EXEIN_BACKTRACE_SIZE];
	char **messages = (char **)NULL;
	int i, trace_size = 0;

	trace_size = backtrace(trace, EXEIN_BACKTRACE_SIZE);
	messages = backtrace_symbols(trace, trace_size);
	printf("[stack trace(%d) ]>>>\n", trace_size);
	for (i=0; i < trace_size; i++)
		printf("%s\n", messages[i]);
	printf("<<<[stack trace]\n");
	free(messages);
}

static void sk_sigsegv_handler(int sig, siginfo_t *si, void *unused){
	switch(sig)
		{
		case SIGSEGV:
			{
			printf("libexnl.sk_sigsegv_handler - Keep alive thread got SIGSEGV at address: 0x%lx\n",(long) si->si_addr);
			stack_trace();
			exit(-1);
			}
		default:
		printf("libexnl.sk_sigsegv_handler - Reecived Signal :%d\n",sig);
		};
}

static void rf_sigsegv_handler(int sig, siginfo_t *si, void *unused){
	switch(sig)
		{
		case SIGSEGV:
			{
			printf("libexnl.rf_sigsegv_handler - Receive feeds thread got SIGSEGV at address: 0x%lx\n",(long) si->si_addr);
			stack_trace();
			signal(sig, SIG_DFL);
			kill(getpid(), sig);
			}
		default:
		printf("libexnl.rf_sigsegv_handler - Reecived Signal :%d\n",sig);
		};
}

static int send_keepalives(void *data){
	exein_shandle 		*uhandle=	((proc_args *)data)->uhandle;
	void			*payload=	((proc_args *)data)->payload;
	struct sigaction	sa = {0};
	//don't think you're smarter. those stack variables are not there by chance

	((proc_args *)data)->loading_done=1;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sk_sigsegv_handler;
	if (sigaction(SIGSEGV, &sa, NULL) == -1){
		printf("Keep alive can't install handler\n");
		}
	while (1){
		DODEBUG("libexnl.send_keepalives - sending keepalive\n");
		memcpy(	NLMSG_DATA(uhandle->nlh_sk), payload, EXEIN_PKT_SIZE); //EXEIN_PKT_SIZE constant
		uhandle->nlh_sk->nlmsg_pid=uhandle->cpid;
		if (sendmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) {
			uhandle->trouble=EXEIN_STAT_SK_ENOMEM;
			continue;
			}
		sleep(5);
		uhandle->trouble=EXEIN_STAT_OK;
		}
	return EXEIN_NOERR;
}

static int receive_feeds(void *data){
	uint16_t		seqn=		0x55aa; //hoping it'll never be matched by chance, I just put fake number there
	uint16_t		*rdata;
	exein_pids		*buf;
	exein_shandle		*uhandle=	((proc_args *)data)->uhandle;
	struct sigaction	sa = {0};
	int			err;

	//don't think you're smarter. those stack variables are not there by chance

	uhandle->msg_rf=		(struct msghdr *) malloc(sizeof(struct msghdr));
	if (!uhandle->msg_rf) exit(-1);
	memcpy(uhandle->msg_rf, uhandle->msg_sk, sizeof(struct msghdr)); //sizeof(struct msghdr) constant
	uhandle->msg_rf->msg_iov=	(struct iovec *) malloc(sizeof(struct iovec));
	if (!uhandle->msg_rf->msg_iov) exit(-1);
	memcpy(uhandle->msg_rf->msg_iov, uhandle->msg_sk->msg_iov, sizeof(struct iovec)); //sizeof(struct iovec)constant
	uhandle->msg_rf->msg_iov->iov_base = (struct nlmsghdr *)malloc(NLMSG_SPACE(EXEIN_PKT_SIZE));
	if (!uhandle->msg_rf->msg_iov->iov_base) exit(-1);
	uhandle->nlh_rf=(struct nlmsghdr *)uhandle->msg_rf->msg_iov->iov_base;
	((proc_args *) data)->loading_done=	1;

	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = rf_sigsegv_handler;
	if (sigaction(SIGSEGV, &sa, NULL) == -1){
		printf("Receive feeds can't install the signal handler.");
		}
	while (1){
		DODEBUG("libexnl.receive_feeds - wait for new message\n");
		if ((err=recvmsg(uhandle->sock_fd, uhandle->msg_rf, 0))<0) {
			printf("recvmsg went wrong %d\n", err);
			uhandle->trouble=EXEIN_STAT_RF_ENLCOM;
			continue;
			}

		rdata = (uint16_t *) NLMSG_DATA(uhandle->nlh_rf);
		if (((exein_prot_reply_t *) rdata)->seq!=seqn) {
			switch (((exein_prot_reply_t *) rdata)->msg_type){
				case EXEIN_MSG_DEL_PID:
					DODEBUG("libexnl.receive_feeds - EXEIN_MSG_DEL_PID received\n");
					if (exein_delete_pid_cb!=NULL) {
                                                (*exein_delete_pid_cb)( ((exein_prot_reply_t *) rdata)->payload[0]);
                                                }

					break;
				case EXEIN_MSG_NEW_PID:
					DODEBUG("libexnl.receive_feeds - EXEIN_MSG_NEW_PID received\n");
					if (exein_new_pid_notify_cb!=NULL) {
						(*exein_new_pid_notify_cb)( ((exein_prot_reply_t *) rdata)->payload[0]);
						}
					break;
				case EXEIN_MSG_FEED:
					DODEBUG("libexnl.receive_feeds - EXEIN_MSG_FEED received {size:'%d', seed:'%d', seq:'%d', pid='%d', pl:[%d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d,  %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d, %d,%d,%d,%d]}\n",
								err, ((exein_prot_reply_t *) rdata)->seed, ((exein_prot_reply_t *) rdata)->seq, ((exein_prot_reply_t *) rdata)->pid,
								((exein_prot_reply_t *) rdata)->payload[0], ((exein_prot_reply_t *) rdata)->payload[1], ((exein_prot_reply_t *) rdata)->payload[2], ((exein_prot_reply_t *) rdata)->payload[3],
								((exein_prot_reply_t *) rdata)->payload[4], ((exein_prot_reply_t *) rdata)->payload[5], ((exein_prot_reply_t *) rdata)->payload[6], ((exein_prot_reply_t *) rdata)->payload[7],
								((exein_prot_reply_t *) rdata)->payload[8], ((exein_prot_reply_t *) rdata)->payload[9], ((exein_prot_reply_t *) rdata)->payload[10], ((exein_prot_reply_t *) rdata)->payload[11],
								((exein_prot_reply_t *) rdata)->payload[12], ((exein_prot_reply_t *) rdata)->payload[13], ((exein_prot_reply_t *) rdata)->payload[14], ((exein_prot_reply_t *) rdata)->payload[15],
								((exein_prot_reply_t *) rdata)->payload[16], ((exein_prot_reply_t *) rdata)->payload[17], ((exein_prot_reply_t *) rdata)->payload[18], ((exein_prot_reply_t *) rdata)->payload[19],
								((exein_prot_reply_t *) rdata)->payload[20], ((exein_prot_reply_t *) rdata)->payload[21], ((exein_prot_reply_t *) rdata)->payload[22], ((exein_prot_reply_t *) rdata)->payload[23],
								((exein_prot_reply_t *) rdata)->payload[24], ((exein_prot_reply_t *) rdata)->payload[25], ((exein_prot_reply_t *) rdata)->payload[26], ((exein_prot_reply_t *) rdata)->payload[27],
								((exein_prot_reply_t *) rdata)->payload[28], ((exein_prot_reply_t *) rdata)->payload[29], ((exein_prot_reply_t *) rdata)->payload[30], ((exein_prot_reply_t *) rdata)->payload[31]);
					DODEBUG("libexnl.receive_feeds - accessing Hash @%p\n", uhandle->pids);
					DODEBUG("libexnl.receive_feeds - test read mmapped memory [%p]=%08x\n", uhandle->pids, *((uint32_t *) uhandle->pids));
					HASH_FIND(hh,uhandle->pids,&(((exein_prot_reply_t *) rdata)->pid),sizeof(uint16_t),buf);
					DODEBUG("libexnl.receive_feeds - suitable buf located @%p\n", buf);
					if ((buf)&&(buf->buffer)) {// there is a buffer, not first time receive this if buf->buffer is null, hook arrived before structure ready. Both cases can't be processed
						DODEBUG("libexnl.receive_feeds - the message we're waiting for (pid=%d)is just received, forward data to app\n", ((exein_prot_reply_t *) rdata)->pid);
						memcpy(buf->buffer, ( ((exein_prot_reply_t *) rdata)->payload), sizeof(uint16_t)*EXEIN_BUFFES_SIZE);//sizeof(uint16_t)*EXEIN_BUFFES_SIZE constant
						sem_post(&buf->semaphore);
						} else {// firs time I receive data for this pid, entry needs to be created
							DODEBUG("libexnl.receive_feeds - received feeds for unknown pid = %d or structure is not yet ready to get data.\n", ((exein_prot_reply_t *) rdata)->pid);
							}
					break;
				default:
					DODEBUG("libexnl.receive_feeds - [##########] CASE DEFAULT  has been reached. Something wrong is going on!!!!\n");
					for (int i=0; i<err; i++) printf("%02x ", *(((char *) rdata)+i) );
				}

			}
		}
	return EXEIN_NOERR;
}





int exein_block_process(exein_shandle *uhandle, uint16_t pid, uint32_t key, uint16_t tag){
	exein_prot_req_t block={
        	.key            = key,
	        .message_id     = EXEIN_MSG_BK,
        	.tag            = tag,
	        .padding        = 0,
        	.pid            = pid,
	        };

	memcpy(	NLMSG_DATA(uhandle->nlh_sk), &block, EXEIN_PKT_SIZE); //EXEIN_PKT_SIZE constant
	uhandle->nlh_sk->nlmsg_pid=pid;
	if (sendmsg(uhandle->sock_fd, uhandle->msg_sk, 0)<0) {
		uhandle->trouble=EXEIN_STAT_SK_ENOMEM;
		return EXEIN_ERR_NLCOM;
		}
	return EXEIN_NOERR;

}

void exein_agent_stop(exein_shandle *uhandle){
        int i;
        exein_pids *buf;

        if (uhandle==NULL) return;
        kill(uhandle->sk_pid, SIGKILL);
        kill(uhandle->rf_pid, SIGKILL);
        close(uhandle->sock_fd);
        free(uhandle->src_addr);
        free(uhandle->dest_addr);
        free(uhandle->msg_sk->msg_iov);
        free(uhandle->msg_sk);
        free(uhandle->nlh_sk);
        free(uhandle->sk_stack);
        mealloc_destroy(uhandle);
}

exein_shandle *exein_agent_start(uint32_t key, uint16_t tag)
{
	proc_args		rf_args;
	proc_args		sk_args;
	exein_shandle		*uhandle;
	pid_t			cpid=		0;
	int 			err;

	DODEBUG("libexnl.exein_agent_start - staring up\n");

	keepalive.key=key;
	keepalive.tag=tag;
	keepalive.message_id=EXEIN_MSG_KA;
	registration.key=key;
	registration.tag=tag;
	registration.message_id=EXEIN_MSG_REG;

        DODEBUG("libexnl.exein_agent_start - allocating memory structures\n");
	uhandle=                (exein_shandle *) BASE2RESERVED(mealloc_init(sizeof(exein_shandle), sizeof(exein_pids)));
	if (!uhandle) return NULL;
	memset(uhandle, 0, sizeof(exein_shandle));
	uhandle->buffers_pool=	sbuff_init();
	uhandle->hash_shm    =  (void *) mealloc_init(0 , sizeof(UT_hash_table) );
	DODEBUG("libexnl.exein_agent_start - mealloc returned reserved pointer = %p for uhandle, %p for buffers_pool, uhandle->hash_shm=%p \n", uhandle, uhandle->buffers_pool, uhandle->hash_shm);
	uhandle->dest_addr=	(struct sockaddr_nl *) malloc(sizeof(struct sockaddr_nl));
	if (!uhandle->dest_addr) {
		free(uhandle);
		return NULL;
		}
	uhandle->src_addr=	(struct sockaddr_nl *) malloc(sizeof(struct sockaddr_nl));
	if (!uhandle->src_addr) {
		free(uhandle->dest_addr);
		free(uhandle);
		return NULL;
		}
	uhandle->msg_sk=	(struct msghdr *) malloc(sizeof(struct msghdr));
	if (!uhandle->msg_sk) {
		free(uhandle->src_addr);
		free(uhandle->dest_addr);
		free(uhandle);
		return NULL;
		}
	memset(uhandle->msg_sk, 0, sizeof(struct msghdr));
	cpid=getpid();
	if ((err=netlink_setup(uhandle, cpid))<0){
		printf("libexnl.exein_agent_start - netlink setup failed.");
		free(uhandle->msg_sk);
		free(uhandle->src_addr);
		free(uhandle->dest_addr);
		free(uhandle);
		return NULL;
		}

	if ((err=netlink_msg_init(EXEIN_PKT_SIZE, cpid, uhandle))<0){
		printf("libexnl.exein_agent_start - netlink message setup failed.");
		free(uhandle->msg_sk->msg_iov->iov_base); //nlh
		free(uhandle->msg_sk->msg_iov);
		free(uhandle->msg_sk);
		free(uhandle->src_addr);
		free(uhandle->dest_addr);
		free(uhandle);
		return NULL;
		}
	uhandle->cpid=cpid;

        DODEBUG("libexnl.exein_agent_start - starting threads\n");
	if (exein_nl_peer_register(uhandle, &registration)==EXEIN_NOERR){
		uhandle->sk_stack=	malloc(EXEIN_SK_STACK_SIZE);
		if (!uhandle->sk_stack) {
			free(uhandle->msg_sk->msg_iov->iov_base); //nlh
			free(uhandle->msg_sk->msg_iov);
			free(uhandle->msg_sk);
			free(uhandle->src_addr);
			free(uhandle->dest_addr);
			free(uhandle);
			return NULL;
			}
		sk_args.uhandle=	uhandle;
		sk_args.payload=	&keepalive;
		sk_args.loading_done=	0;
		uhandle->sk_pid=	clone(&send_keepalives, (char *) uhandle->sk_stack+EXEIN_SK_STACK_SIZE, CLONE_VM, &sk_args);
		uhandle->rf_stack=	malloc(EXEIN_RF_STACK_SIZE);
		if (!uhandle->rf_stack) {
			free(uhandle->sk_stack);
			free(uhandle->msg_sk->msg_iov->iov_base); //nlh
			free(uhandle->msg_sk->msg_iov);
			free(uhandle->msg_sk);
			free(uhandle->src_addr);
			free(uhandle->dest_addr);
			free(uhandle);
			return NULL;
			}
		rf_args.uhandle=	uhandle;
		rf_args.loading_done=	0;
		uhandle->rf_pid=	clone(&receive_feeds, (char *) uhandle->rf_stack+EXEIN_RF_STACK_SIZE, CLONE_VM, &rf_args);
		} else {
			printf("libexnl.exein_agent_start - threads setup failed.");
			free(uhandle->msg_sk->msg_iov->iov_base); //nlh
			free(uhandle->msg_sk->msg_iov);
			free(uhandle->msg_sk);
			free(uhandle->src_addr);
			free(uhandle->dest_addr);
			free(uhandle);
			return NULL;
			}
        DODEBUG("libexnl.exein_agent_start - sync with threads\n");
	while (sk_args.loading_done==0) sleep(1);
	while (rf_args.loading_done==0) sleep(1);
        DODEBUG("libexnl.exein_agent_start - setup done\n");
	uhandle->key=key;
	uhandle->tag=tag;
	return uhandle;
}


