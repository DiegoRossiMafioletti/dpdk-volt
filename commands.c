#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <inttypes.h>

#include <rte_common.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_string.h>
#include <cmdline_parse_num.h>
#include <cmdline.h>


/*** quit ***/
/* exit application */

struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void
cmd_quit_parsed(__rte_unused void *parsed_result,
		struct cmdline *cl,
		__rte_unused void *data)
{
	cmdline_quit(cl);
}

cmdline_parse_token_string_t cmd_quit_tok =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "exit application",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_quit_tok,
		NULL,
	},
};



cmdline_parse_ctx_t main_ctx[] = {
		(cmdline_parse_inst_t *)&cmd_quit,
		(cmdline_parse_inst_t *)&cmd_ambig_1,
		(cmdline_parse_inst_t *)&cmd_ambig_2,
		(cmdline_parse_inst_t *)&cmd_single,
		(cmdline_parse_inst_t *)&cmd_single_long,
		(cmdline_parse_inst_t *)&cmd_num,
		(cmdline_parse_inst_t *)&cmd_get_history_bufsize,
		(cmdline_parse_inst_t *)&cmd_clear_history,
		(cmdline_parse_inst_t *)&cmd_autocomplete_1,
		(cmdline_parse_inst_t *)&cmd_autocomplete_2,
	NULL,
};