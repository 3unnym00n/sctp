#include "sctp_proxy.h"




int send_to_target(int s, 
                                    const void *msg, 
                                    size_t len,
                                    struct sockaddr *to, 
                                    socklen_t tolen,
                                    uint32_t ppid, 
                                    uint32_t flags,
                                    uint16_t stream_no, 
                                    uint32_t timetolive,
                                    uint32_t context)
{
	int status = -1;
	do 
	{
		int error = sctp_sendmsg(s, msg, len, to, tolen, ppid, flags, stream_no, timetolive, context);
		if (len != error)
		{
			perror("sctp_sendmsg");
			break;
		}
		status = 0;
	} while (0);
	return status;
}

int recv_from_target(int sk, 
                                        void *msg,
                                        size_t len,
                                        struct sockaddr *from,
                                        socklen_t *fromlen,
                                        struct sctp_sndrcvinfo *sinfo,
                                        int *msg_flags)
{
	int recv_len = -1;
	do 
	{
        recv_len = sctp_recvmsg(sk, msg, len, from, fromlen, sinfo, msg_flags);
        if (-1 == recv_len)
        {
            perror("sctp_recvmsg");
            break;
        }
	} while (0);

	return recv_len;	
}
int create_socket(int domain, int type, int protocol)
{
   
    int sk = socket(domain, type, protocol);
    if (-1 == sk)
    {
        perror("socket");
    }
    return sk;	
}

int set_sock_opt(int sk, int optname, const void *optval, socklen_t optlen)
{

    int error = setsockopt(sk, SOL_SCTP, optname, optval, optlen);
    if (error)
    {
        perror("setsockopt");
    }
    return error;
}


int try_bind(int sk, struct sockaddr *addr, socklen_t addrlen)
{
    int error = bind(sk, addr, addrlen);
    if (-1 == error)
    {
        perror("bind");
    }
    return error;
}


static inline void * try_malloc(size_t size)
{
    void *buf = malloc(size);
    if (NULL == buf)
    {
        printf("malloc failed ...");
        exit(-1);
    }
    return buf;
}



/* Check if a buf/msg_flags matches a notification, its type, and possibly an
 * additional field in the corresponding notification structure.
 */
int check_buf_notification(void *buf, int datalen, int msg_flags,
			    int expected_datalen, uint16_t expected_sn_type,
			    uint32_t expected_additional)
{
	union sctp_notification *sn;
	
	if (!(msg_flags & MSG_NOTIFICATION))
    {
        //printf( "Got a datamsg, expecting notification");
        printf( "Got a datamsg");
        return 1;
    }

	if (expected_datalen <= 0)
    {
		return -1;
    }

	if (datalen != expected_datalen)
    {
        printf("\nGot a notification of unexpected "
			 "length:%d, expected length:%d\n", datalen,
			 expected_datalen);
    }	
	sn = (union sctp_notification *)buf;
	if (sn->sn_header.sn_type != expected_sn_type)
    {
        printf("\nUnexpected notification:%d"
            "expected:%d\n", sn->sn_header.sn_type,
            expected_sn_type);
    }
	switch(sn->sn_header.sn_type)
    {
	case SCTP_ASSOC_CHANGE:
		if (sn->sn_assoc_change.sac_state != expected_additional)
			printf("\nUnexpected sac_state:%d "
				 "expected:%d\n", sn->sn_assoc_change.sac_state,
				  expected_additional);
		break;
	default:
		break;
	}
    return 0;
}



int main()
{
    sockaddr_storage_t proxy = {0};
    sockaddr_storage_t target = {0};
    sockaddr_storage_t msgname;
    struct sctp_event_subscribe subscribe;
    int pf_class = PF_INET;
    int sk = 0 ; 

    uint32_t ppid;
    uint32_t stream;
    static char *message = "Hello world\n";
    size_t buflen = 0;
    char *big_buffer = NULL;
    socklen_t msgname_len;

    struct sctp_sndrcvinfo sinfo;
    int offset, msg_flags;
    int error = 0;
    int result = 0;

    // v6 也用不着
    // 源地址配置
    proxy.v4.sin_family = AF_INET;
    proxy.v4.sin_port = htons(OUTBOUND_LOCAL_PORT);
    proxy.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
    /*inet_pton(AF_INET, "1.2.3.4",
        &proxy.v4.sin_addr.s_addr);*/
    
    // 目标地址配置
    target.v4.sin_family = AF_INET;
    target.v4.sin_port = htons(OUTBOUND_REMOTE_PORT);
    target.v4.sin_addr.s_addr = SCTP_IP_LOOPBACK;
     /*inet_pton(AF_INET, "1.2.3.4",
        &target.v4.sin_addr.s_addr);*/



    sk = create_socket(pf_class, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (sk == -1)
    {
        return -1;
    }
    
    memset(&subscribe, 0, sizeof(subscribe));
    subscribe.sctp_data_io_event = 1;
    subscribe.sctp_association_event = 1;
    subscribe.sctp_send_failure_event = 1;
    set_sock_opt(sk, SCTP_EVENTS, &subscribe, sizeof(subscribe));

    /* Bind these sockets to the test ports.  */
    try_bind(sk, &proxy.sa, sizeof(proxy));
    buflen = REALLY_BIG;
    big_buffer = try_malloc(buflen);
    while (1)
    {
        ppid = rand();
        stream = 1;

        // 发送给目标机
        send_to_target(sk, message, strlen(message) + 1,
            (struct sockaddr *)&target, sizeof(target),
            ppid, 0, stream, 0, 0);

        // 然后接收目标机
        //buflen = REALLY_BIG;
        //big_buffer = try_malloc(buflen);
        msgname_len = sizeof(msgname);
        msg_flags = 0;

        while (1)
        {
            memset(big_buffer, 0, buflen);
            error = recv_from_target(sk, big_buffer, buflen,
                (struct sockaddr *)&msgname, &msgname_len,
                &sinfo, &msg_flags);

            printf("\nbigbuffer(%d): %s \n",  error, big_buffer);
            hexdump(big_buffer, error);

            // 如果是 data 类型，接收并回传 
            result = check_buf_notification(big_buffer, error, msg_flags,
                sizeof(struct sctp_assoc_change),
                SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
            if (result)
            {
                break;
            }

        }
        sleep(2);
    }
    
    


    /*
    // 问题来了，我是想要数据，而不是要 notify 这些东西
    // 第一次接收到的是 notification
    check_buf_notification(big_buffer, error, msg_flags,
        sizeof(struct sctp_assoc_change),
        SCTP_ASSOC_CHANGE, SCTP_COMM_UP);
    
    // 第二次接收到的是 data
    error = recv_from_target(sk, big_buffer, buflen,
        (struct sockaddr *)&msgname, &msgname_len,
        &sinfo, &msg_flags);
    printf("\nbigbuffer(%d): %s \n",  error, big_buffer);
    hexdump(big_buffer, error);
    check_buf_notification(big_buffer, error, msg_flags,
        sizeof(struct sctp_assoc_change),
        SCTP_ASSOC_CHANGE, SCTP_COMM_UP);*/
    /*
    error = recv_from_target(sk, big_buffer, buflen,
    (struct sockaddr *)&msgname, &msgname_len,
    &sinfo, &msg_flags);

    printf("\nbigbuffer(%d): %s \n",  error, big_buffer);
    hexdump(big_buffer, error);
   
    error = recv_from_target(sk, big_buffer, buflen,
    (struct sockaddr *)&msgname, &msgname_len,
    &sinfo, &msg_flags);

    printf("\nbigbuffer(%d): %s \n",  error, big_buffer);
    hexdump(big_buffer, error);*/
    



	return 0;
}