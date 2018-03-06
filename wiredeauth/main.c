


#include <stdio.h>
#include "deauth.h"



int main(int argc, char **argv) {

	struct deauth_method *method;
	struct deauth_ctx *ctx;

	if ( !(method = deauth_method_new()) )
		return -1;

	if ( deauth_method_register(method) < 0 ) {
		deauth_method_destroy(method);
		return -1;
	}

	if ( !(ctx = method->ctx_new()) ) {
		deauth_method_destroy(method);
		return -1;
	}

	if ( method->config(ctx, argc, argv) < 0 ) {
		method->ctx_destroy(ctx);
		deauth_method_destroy(method);
		return -1;
	}

	if ( method->init(ctx) < 0 ) {
		method->ctx_destroy(ctx);
		deauth_method_destroy(method);
		return -1;
	}

	while ( 1 ) {
		if ( method->gather_aps(ctx) < 0 )
			break;
		if ( method->deauth_aps(ctx) < 0 )
			break;
	}

	method->exit(ctx);
	method->ctx_destroy(ctx);
	deauth_method_destroy(method);

	return 0;

}



