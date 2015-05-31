#ifndef __SCTP_PROXY_H__
#define __SCTP_PROXY_H__
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/sctp.h>
#include <unistd.h>

#define  INBOUND_LOCAL_PORT				4444
#define  INBOUND_REMOTE_PORT			4444
#define  OUTBOUND_LOCAL_PORT		50001
#define  OUTBOUND_REMOTE_PORT	5000

#define REALLY_BIG 65535

#define SCTP_IP_LOOPBACK  htonl(0x7f000001)

typedef union {
    struct sockaddr_in v4;	
    struct sockaddr_in6 v6;
    struct sockaddr sa;	
} sockaddr_storage_t;

extern void hexDump (void *addr, int len);

#endif

