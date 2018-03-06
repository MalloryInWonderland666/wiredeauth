


#ifndef __SET_CHANNEL_H
#define __SET_CHANNEL_H



#include <sys/socket.h>
#include <linux/nl80211.h>
#include <netlink/genl/ctrl.h>



extern unsigned int if_nametoindex (const char *__ifname);



struct nl80211_state {
    struct nl_sock *nl_sock;
    struct nl_cache *nl_cache;
    struct genl_family *nl80211;
};



int set_channel(char *ifname, int channel);



#endif /* __SET_CHANNEL_H */

