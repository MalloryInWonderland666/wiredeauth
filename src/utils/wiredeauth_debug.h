


/*!

	@file wiredeauth_debug.h

	@brief Functions for conditional debug output.

	The current implementation has no debug levels or
	even any run-time configurability. The program is
	either compiled in debug mode or in silent mode.

*/



#ifndef WIREDEAUTH_DEBUG_H
#define WIREDEAUTH_DEBUG_H



#include <stdio.h>



#ifdef WIREDEAUTH_DEBUG
#define PRINTF(...) fprintf(stdout, __VA_ARGS__)
#else /* WIREDEAUTH_DEBUG */
#define PRINTF(...) /* stub */
#endif /* WIREDEAUTH_DEBUG */



#endif /* WIREDEAUTH_DEBUG_H */



