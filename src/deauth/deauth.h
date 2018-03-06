


#ifndef DEAUTH_H
#define DEAUTH_H



#include <sys/types.h>



#define HOST_NAME	"phymod0"
#define PROG_NAME	"wiredeauth"

#define SSID_MAXSZ	256
#define PKT_MAXSZ	2048
#define N_CHANNELS	14
#define MAX_SEQNUM	256

/*

	@brief Extract the header length from the radiotap header.

*/
#define RTAP_HDRLEN(pkt) (((int)(((unsigned char*)(pkt))[2]))|(((int)(((unsigned char*)(pkt))[3]))<<8))

/*

	@brief Iterate over channels.

*/
#define CHANNELS_FOREACH(statement) ({					\
	int __i__;							\
	for (__i__ = 0; __i__ < N_CHANNELS; __i__++) {			\
		int chan_index = __i__;					\
		int channel = chan_index + 1;				\
		statement;						\
	}								\
})

/*

	@brief Cycle over channels ending with cyc_till.

*/
#define CHANNELS_CYCLE(cyc_till, statement) ({				\
	int __i__;							\
	for (__i__ = 0; __i__ < N_CHANNELS; __i__++) {			\
		int chan_index = (__i__ + (cyc_till)) % 14;		\
		int channel = chan_index + 1;				\
		statement;						\
	}								\
})



/*!

	@brief Context for the functions in struct deauth_method.

	This struct contains the state information to pass on to the
	functions in the deauth_method struct

*/
struct deauth_ctx {

	int n_deauth_rounds;

	char *if_name;
	int sock_fd;

	/// Note: One list per channel
	struct accesspoint_list *target_aps[N_CHANNELS];

#ifdef DEAUTH_METHOD_WLD
	int allowed_channels[N_CHANNELS];
	int current_channel;
	union {
		int n_allowed_channels;
		int channels_specified;
	};

	int probes_per_channel;
	int channel_probes_remaining;
	int probe_addr_limit; //!< Limit the size of the probing queue
	int probe_time_limit; //!< Limit the probing time (seconds)
	int probe_busy;
	int probe_expiry_time;

	struct macaddr {
		struct macaddr *next;
		unsigned char mac[6];
	} *mac_blacklist; //!< BSSID's exempted from deauthentication
#endif /* DEAUTH_METHOD_WLD */

};

/*!

	@brief Pointers to statically linked deauth method functions.

*/
struct deauth_method {

	/*! Allocate context and initialize with defaults */
	struct deauth_ctx *(*ctx_new)(void);

	/*! Configure initial context from arguments */
	int (*config)(struct deauth_ctx *ctx, int argc, char **argv);

	/*! Prepare context for deauths */
	int (*init)(struct deauth_ctx *ctx);

	/*! Probe for and select potential access point addresses */
	int (*gather_aps)(struct deauth_ctx *ctx);

	/*! Deauthenticate selected access points */
	int (*deauth_aps)(struct deauth_ctx *ctx);

	/*! Revert .init() changes */
	void (*exit)(struct deauth_ctx *ctx);

	/*! Free all allocations from .ctx_new() and .config() */
	void (*ctx_destroy)(struct deauth_ctx *ctx);

};



struct deauth_method *deauth_method_new(void);
int deauth_method_register(struct deauth_method *method);
void deauth_method_destroy(struct deauth_method *method);



#endif /* DEAUTH_H */



