


/*!

	@file arg_parse.c

	@brief Callback-based argument parser

	TODO:
		- None

*/



#ifndef ARG_PARSE_C
#define ARG_PARSE_C



#include <stdio.h>
#include "arg_parse.h"
#include "wiredeauth_debug.h"



#define ARG_FAULT(arg)		((arg)[1] == 0)
#define IS_OPT(arg)		((arg)[0] == '-')
#define IS_SHORT(arg)		((arg)[1] != '-')
#define IS_LONG(arg)		((arg)[1] == '-')
#define OPT_SHORT(arg)		((arg)[1])
#define OPT_LONG(arg)		((arg) + 2)
#define OPTSTR(arg)		(IS_SHORT(arg)?OPTSTR_SHORT(arg):OPTSTR_LONG(arg))



/*

	Return -1 indicating unavailability

*/
static int short_cb_unavailable(char opt, char *val, void *cb_data) {

	return -1;

}

/*

	Return -1 indicating unavailability

*/
static int long_cb_unavailable(char *opt, char *val, void *cb_data) {

	return -1;

}

/*

	Returns 0 on success, -1 on failure

*/
int parse_args(int argc, char **argv, parser_cb_short short_cb,
		parser_cb_long long_cb, void *cb_data, char *usage_str) {

	int i;
	char *current_opt = NULL;

	if (usage_str == NULL)
		usage_str = DEFAULT_USAGE;

	if (short_cb == NULL)
		short_cb = short_cb_unavailable;

	if (long_cb == NULL)
		long_cb = long_cb_unavailable;

	for (i = 1; i < argc; i++) {

		int res;
		char *arg = argv[i];

		if (IS_OPT(arg)) {
			current_opt = arg;
			continue;
		}

		if (!current_opt) {
			/* argval provided without an argopt */
			PRINTF("%s\n", usage_str);
			return -1;
		}

		if (IS_SHORT(current_opt))
			res = short_cb(OPT_SHORT(current_opt), arg, cb_data);
		else
			res = long_cb(OPT_LONG(current_opt), arg, cb_data);

		if (res == 0)
			continue;

		/* Failure from one of the callbacks */
		PRINTF("%s\n", usage_str);
		return -1;

	}

	return 0;

}




#endif /* ARG_PARSE_C */



