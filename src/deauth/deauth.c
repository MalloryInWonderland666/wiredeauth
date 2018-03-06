


/*!

	@file deauth.c

	@brief Register a deauthentication method from
	the set of statically linked modules.

*/



#ifndef DEAUTH_C
#define DEAUTH_C



#include <stdio.h>
#include <stdlib.h>

#include "deauth.h"
#include "wiredeauth_debug.h"



/*!

	@brief Check if the necessary methods are
	loaded in a deauth_method struct.

	@param method Pointer to the deauth_method
	struct to validate.

	@return 0 if the required functions are
	loaded and -1 otherwise.

*/
static int method_validate(struct deauth_method *method) {

	if ( !method->ctx_new )
		return -1;

	if ( !method->config )
		return -1;

	if ( !method->init )
		return -1;

	if ( !method->gather_aps )
		return -1;

	if ( !method->deauth_aps )
		return -1;

	if ( !method->exit )
		return -1;

	if ( !method->ctx_destroy )
		return -1;

	return 0;

}

/*!

	@brief Allocate memory for a deauth_method.

	@return Pointer to a deauth_method struct.

*/
struct deauth_method *deauth_method_new(void) {

	struct deauth_method *method =
		(struct deauth_method*)calloc(1, sizeof(struct deauth_method));

	return method;

}

/*!

	@brief Free memory for a deauth_method.

	@param method deauth_method to be freed.

*/
void deauth_method_destroy(struct deauth_method *method) {

	free(method);

	return;

}

/*!

	@brief Register a statically linked deauth method.

	The deauthentication method to use will be specified
	on compilation. The corresponding register function
	will be hard-coded here and invoked. Note that the
	register function declaration is placed immediately
	before the call.

	@param method Empty deauth_method struct registered
	at program initialization.

	@return 0 on success or -1 on failure.

	TODO:
		- Simplify the requirements for method implementations
		by supplying the common functionality when registering
		the module in _this_ function.

*/
int deauth_method_register(struct deauth_method *method) {

	int retval = 1;

#ifdef DEAUTH_METHOD_ASSISTED

	if ( retval != 1 ) {
		PRINTF("deauth_method_register(): Multiple deauth methods specified (aborting).\n");
		return -1;
	}

	int deauth_assisted_register(struct deauth_method*);
	retval = deauth_assisted_register(method);

#endif /* DEAUTH_METHOD_ASSISTED */

#ifdef DEAUTH_METHOD_WLD

	if ( retval != 1 ) {
		PRINTF("deauth_method_register(): Multiple deauth methods specified (aborting).\n");
		return -1;
	}

	int deauth_wld_register(struct deauth_method*);
	retval = deauth_wld_register(method);

#endif /* DEAUTH_METHOD_WLD */

#ifdef DEAUTH_METHOD_STATIC_FILE

	if ( retval != 1 ) {
		PRINTF("deauth_method_register(): Multiple deauth methods specified (aborting).\n");
		return -1;
	}

	int deauth_static_file_register(struct deauth_method*);
	retval = deauth_static_file_register(method);

#endif /* DEAUTH_METHOD_STATIC_FILE */

#ifdef DEAUTH_METHOD_ARGS

	if ( retval != 1 ) {
		PRINTF("deauth_method_register(): Multiple deauth methods specified (aborting).\n");
		return -1;
	}

	int deauth_args_register(struct deauth_method*);
	retval = deauth_args_register(method);

#endif /* DEAUTH_METHOD_ARGS */

#ifdef DEAUTH_METHOD_HARDCODE

	if ( retval != 1 ) {
		PRINTF("deauth_method_register(): Multiple deauth methods specified (aborting).\n");
		return -1;
	}

	int deauth_hardcode_register(struct deauth_method*);
	retval = deauth_hardcode_register(method);

#endif /* DEAUTH_METHOD_HARDCODE */

	if ( retval == 1 ) {
		PRINTF("deauth_method_register(): No deauth methods specified (aborting).\n");
		return -1;
	}

	if ( method_validate(method) < 0 ) {
		PRINTF("Deauth method not registered properly (aborting).\n");
		return -1;
	}

	return retval;

}



#endif /* DEAUTH_C */



