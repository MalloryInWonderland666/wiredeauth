


/*!

	@file raw_socket.h

	@brief Simplified interface for raw socket communication.

*/



#ifndef RAW_SOCKET_H
#define RAW_SOCKET_H



#include "hostapd_common.h"



#define PKT_MAXSZ 2048



int rawsock_new(char *if_name, int protocol);
int rawsock_recv(int sock_fd, u8 *buffer, int usecs_remaining);
int rawsock_send(int sock_fd, u8 *data, int len);
int rawsock_close(int sock_fd);



#endif /* RAW_SOCKET_H */



