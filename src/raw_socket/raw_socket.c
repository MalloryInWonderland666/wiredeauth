


/*!

	@file raw_socket.c

	@brief Simplified interface for raw socket communication.

*/



#ifndef RAW_SOCKET_C
#define RAW_SOCKET_C



#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "raw_socket.h"
#include "wiredeauth_debug.h"



//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////

/*!

	@brief Open a new raw socket for frame injection.

	@param if_name Name of the wireless interface to open
	the socket on

	@param protocol Protocol to use (usually ETH_P_ALL)

	@return The socket descriptor or -1 on failure

*/
int rawsock_new(char *if_name, int protocol) {

	int sock_fd;
	struct sockaddr_ll sll;
	struct ifreq ifr;

	sock_fd = socket(PF_PACKET, SOCK_RAW, htons(protocol));
	if ( sock_fd < 0 ) {
		perror("Socket initialization failed");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	memset(&ifr, 0, sizeof(ifr));

	/* Get interface index */
	strncpy((char*)ifr.ifr_name, if_name, IFNAMSIZ);
	if ( ioctl(sock_fd, SIOCGIFINDEX, &ifr) < 0 ) {
		PRINTF("Device %s not found.\n", if_name);
		return -1;
	}

	/* Bind sock_fd to interface if_name */
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol);
	if ( bind(sock_fd, (struct sockaddr*)&sll, sizeof(sll)) < 0 ) {
		PRINTF("bind() failed on interface %s.\n", if_name);
		return -1;
	}

	return sock_fd;

}

/*!

	@brief Receive a packet from a raw socket.

	@param sock_fd Socket descriptor for raw injection/monitoring.
	@param buffer Pointer to the receiving buffer.
	@param usec_limit Number of microseconds to wait for the receive.

	@return Size of the packet, 0 on timeout, or -1 on failure.

*/
int rawsock_recv(int sock_fd, u8 *buffer, int usec_limit) {

	fd_set rfds;
	int recv_len, res;
	struct timeval tv = {
		.tv_sec = usec_limit / 1000000,
		.tv_usec = usec_limit % 1000000
	};

	FD_ZERO(&rfds);
	FD_SET(sock_fd, &rfds);

	res = select(sock_fd + 1, &rfds, NULL, NULL, &tv);

	if ( res < 0 ) {
		perror("rawsock_recv::select()");
		return -1;
	} else if ( res == 0 ) {
		return 0;
	}

	recv_len = recv(sock_fd, buffer, PKT_MAXSZ, 0);

	if ( recv_len < 0 ) {
		perror("rawsock_recv");
		return -1;
	}

	return recv_len;

}

/*!

	@brief Send a packet on a raw socket.

	@param sock_fd Socket descriptor for raw injection/monitoring.
	@param data Pointer to the sending data.
	@param len Length of the data to send.

	@return 0 on success or -1 on failure.

*/
int rawsock_send(int sock_fd, u8 *data, int len) {

	while ( len ) {

		int n;

		if ( (n = write(sock_fd, data, len)) < 0 ) {
			perror("rawsock_send");
			return -1;
		}

		data += n;
		len -= n;

	}

	return 0;

}

/*!

	@brief Close a raw socket.

	@param sock_fd Socket descriptor.

	@return 0 on success or -1 on failure.

*/
int rawsock_close(int sock_fd) {

	return close(sock_fd);

}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////



#endif /* RAW_SOCKET_C */



