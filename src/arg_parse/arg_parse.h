


#ifndef ARG_PARSE_H
#define ARG_PARSE_H

#define DEFAULT_USAGE "\nUsage for this program is not available!\n\n"



/*

	Must return 0 on success and -1 on failure

*/
typedef int (*parser_cb_short)(char opt, char *val, void *cb_data);
typedef int (*parser_cb_long)(char *opt, char *val, void *cb_data);



int parse_args(int argc, char **argv, parser_cb_short short_cb,
		parser_cb_long long_cb, void *cb_data, char *usage_str);



#endif /* ARG_PARSE_H */



