


#ifndef __SET_CHANNEL_C
#define __SET_CHANNEL_C



#include <sys/socket.h>
#include <linux/nl80211.h>
#include <linux/wireless.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>

#include "set_channel.h"
#include "wiredeauth_debug.h"



struct nl80211_state state;



static int linux_nl80211_init(struct nl80211_state *state) {

    state->nl_sock = nl_socket_alloc();

    genl_connect(state->nl_sock);

    genl_ctrl_alloc_cache(state->nl_sock, &state->nl_cache);

    state->nl80211 = genl_ctrl_search_by_name(state->nl_cache, "nl80211");

    return 0;

}

static void nl80211_cleanup(struct nl80211_state *state) {

    genl_family_put(state->nl80211);

    nl_cache_free(state->nl_cache);

    nl_socket_free(state->nl_sock);

}

static int linux_set_channel_nl80211(char *ifname, int channel) {

	unsigned int devid=if_nametoindex(ifname);

	if ( devid < 1 )
		return 0;

	unsigned int freq;
	if ( channel < 14 )
		freq = 2407 + 5*channel;
	else
		freq = 2484;

	struct nl_msg *msg = nlmsg_alloc();

	genlmsg_put(
		msg, 0, 0,
		genl_family_get_id(state.nl80211),
		0, 0,
		NL80211_CMD_SET_WIPHY,
		0
	);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devid);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_NO_HT);

	nl_send_auto_complete(state.nl_sock, msg);
	nlmsg_free(msg);

nla_put_failure:

	return 0;

}

int set_channel(char *ifname, int channel) {

	if (
			channel < 1
		||	channel > 14
	)
		return -1;

	linux_nl80211_init(&state);

	linux_set_channel_nl80211(ifname, channel);

	nl80211_cleanup(&state);

	return 0;

}



#endif /* __SET_CHANNEL_C */

