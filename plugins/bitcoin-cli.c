/* Code for talking to bitcoind. */
#include "bitcoin/base58.h"
#include "bitcoin/block.h"
#include "bitcoin/feerate.h"
#include "bitcoin/script.h"
#include "bitcoin/shadouble.h"
#include "lightningd/lightningd.h"
#include "lightningd/log.h"
#include <ccan/cast/cast.h>
#include <ccan/io/backend.h>
#include <ccan/io/io.h>
#include <ccan/io/io_plan.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/str/hex/hex.h>
#include <ccan/take/take.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/json_helpers.h>
#include <common/memleak.h>
#include <common/timeout.h>
#include <common/utils.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/bitcoind.h>
#include "bitcoin_cli.h"
#include <bitcoin_rpc.h>
#include <lightningd/chaintopology.h>
#include <stdio.h>

/* Bitcoind's web server has a default of 4 threads, with queue depth 16.
 * It will *fail* rather than queue beyond that, so we must not stress it!
 *
 * This is how many request for each priority level we have.
 */
#define BITCOIND_MAX_PARALLEL 4
#define DEFAULT_RPCCONNECT "127.0.0.1"
#define DEFAULT_HTTP_CLIENT_TIMEOUT 900

static void next_brpc(struct bitcoind *bitcoind, enum bitcoind_prio prio);

/* For printing: simple string of args. */

static void retry_brpc(struct bitcoin_rpc *brpc)
{
	list_add_tail(&brpc->bitcoind->pending[brpc->prio], &brpc->list);
	next_brpc(brpc->bitcoind, brpc->prio);
}

/* We allow 60 seconds of spurious errors, eg. reorg. */
static void brpc_failure(struct bitcoind *bitcoind, struct bitcoin_rpc *brpc,
			 int exitstatus)
{
	struct timerel t;

	if (!bitcoind->error_count)
		bitcoind->first_error_time = time_mono();

	t = timemono_between(time_mono(), bitcoind->first_error_time);
	if (time_greater(t, time_from_sec(bitcoind->retry_timeout)))
		fatal("%s exited %u (after %u other errors) '%.*s'; "
		      "we have been retrying command for "
		      "--bitcoin-retry-timeout=%"PRIu64" seconds; "
		      "bitcoind setup or our --bitcoin-* configs broken?",
              brpc->cmd,
		      exitstatus,
		      bitcoind->error_count,
		      (int)bcli->output_bytes,
		      bcli->output,
		      bitcoind->retry_timeout);

	log_unusual(bitcoind->log, "%s exited with status %u", brpc->cmd,
		    exitstatus);

	bitcoind->error_count++;

	/* reset rpc status */
	brpc->exitstatus = RPC_FAIL;
	brpc->errorcode = 0;
	tal_free(brpc->output);

	/* Retry in 1 second (not a leak!) */
	notleak(new_reltimer(&bitcoind->ld->timers, brpc, time_from_sec(1),
			     retry_brpc, brpc));
}

static void brpc_finished(struct io_conn *conn, struct bitcoin_rpc *brpc)
{
	struct bitcoind *bitcoind = brpc->bitcoind;
	enum bitcoind_prio prio = brpc->prio;
	bool ok;
	u64 msec = time_to_msec(time_between(time_now(), brpc->start));

	/* If it took over 10 seconds, that's rather strange. */
	if (msec > 10000)
		log_unusual(bitcoind->log,
			    "bitcoin-rpc: finished %s (%" PRIu64 " ms)",
			    brpc->cmd, msec);

	assert(bitcoind->num_requests[prio] > 0);

	handle_http_response(brpc->output, brpc);

	if ((brpc->exitstatus == RPC_FAIL) ||
	    ((!brpc->rpc_error_ok) && (brpc->exitstatus == RPC_ERROR))) {
		log_unusual(bitcoind->log, "RPC: exit fail %d",
			    brpc->exitstatus);
		brpc_failure(bitcoind, brpc, brpc->exitstatus);
		bitcoind->num_requests[prio]--;
		goto done;
	}

	if (brpc->exitstatus == RPC_SUCCESS)
		bitcoind->error_count = 0;

	/* Don't continue if were only here because we were freed for shutdown
	 */
	if (bitcoind->shutdown) {
		tal_free(brpc->cmd);
		tal_free(brpc->request);
		tal_free(brpc->output);
		tal_free(brpc);
		return;
	}

	db_begin_transaction(bitcoind->ld->wallet->db);
	ok = brpc->process(brpc);
	db_commit_transaction(bitcoind->ld->wallet->db);

	bitcoind->num_requests[brpc->prio]--;

	if (!ok) {
		brpc_failure(bitcoind, brpc, brpc->exitstatus);
	} else {
		tal_free(brpc->cmd);
		tal_free(brpc->request);
		tal_free(brpc->output);
		tal_free(brpc);
	}

done:
	next_brpc(bitcoind, prio);
}

static struct io_plan *read_more(struct io_conn *conn, struct bitcoin_rpc *brpc)
{
	brpc->output_bytes += brpc->new_output;
	if (brpc->output_bytes == tal_count(brpc->output))
		tal_resize(&brpc->output, brpc->output_bytes * 2);
	return io_read_partial(conn, brpc->output + brpc->output_bytes,
			       tal_count(brpc->output) - brpc->output_bytes,
			       &brpc->new_output, read_more, brpc);
}

static struct io_plan *output_init(struct io_conn *conn,
				   struct bitcoin_rpc *brpc)
{
	brpc->output_bytes = brpc->new_output = 0;
	brpc->output = tal_arr(brpc, char, 1000);
	return read_more(conn, brpc);
}

static void next_brpc(struct bitcoind *bitcoind, enum bitcoind_prio prio)
{
	struct bitcoin_rpc *brpc;
	bool ret;
	struct io_conn *conn;

	if (bitcoind->num_requests[prio] >= bitcoind->rpcthreads)
		return;

	brpc = list_pop(&bitcoind->pending[prio], struct bitcoin_rpc, list);
	if (!brpc)
		return;

	ret = rpc_request(brpc);
	if (!ret) {
		log_unusual(bitcoind->log, "next_brpc Failed: %s",
			    strerror(errno));
		abort();
		return;
	}

	brpc->start = time_now();

	bitcoind->num_requests[prio]++;

	/* Create two connections, one read-only on of rpc socket, and one
	 * write-only on rpc socket */
	conn = notleak(io_new_conn(bitcoind, brpc->fd, output_init, brpc));
	io_set_finish(conn, brpc_finished, brpc);
}

static bool is_literal(const char *arg)
{
	size_t arglen = strlen(arg);
	return strspn(arg, "0123456789") == arglen || streq(arg, "true") ||
	       streq(arg, "false") || streq(arg, "null") ||
	       (arg[0] == '{' && arg[arglen - 1] == '}') ||
	       (arg[0] == '[' && arg[arglen - 1] == ']') ||
	       (arg[0] == '"' && arg[arglen - 1] == '"');
}

static void add_input(char **cmd, const char *input, bool last)
{
	/* Numbers, bools, objects and arrays are left unquoted,
	 * and quoted things left alone. */
	if (is_literal(input))
		tal_append_fmt(cmd, "%s", input);
	else
		tal_append_fmt(cmd, "\"%s\"", input);
	if (!last)
		tal_append_fmt(cmd, ", ");
}

static bool process_donothing(struct bitcoin_rpc *bcrpc UNUSED) { return true; }

/* If stopper gets freed first, set process() to a noop. */
static void stop_process_brpc(struct bitcoin_rpc **stopper)
{
	(*stopper)->process = process_donothing;
	(*stopper)->stopper = NULL;
}

/* It rpc command finishes first, free stopper. */
static void remove_stopper(struct bitcoin_rpc *brpc)
{
	/* Calls stop_process_brpc, but we don't care. */
	tal_free(brpc->stopper);
}

static struct bitcoin_rpc *
start_bitcoin_rpc(struct bitcoind *bitcoind, const tal_t *ctx,
		  bool (*process)(struct bitcoin_rpc *), bool rpc_error_ok,
		  enum bitcoind_prio prio, void *cb, void *cb_arg, char *cmd,
		  ...)
{
	va_list ap;
	struct bitcoin_rpc *brpc = tal(ctx, struct bitcoin_rpc);
	const char *arg, *next_arg;

	brpc->bitcoind = bitcoind;
	brpc->process = process;
	brpc->cb = cb;
	brpc->cb_arg = cb_arg;
	brpc->prio = prio;
	brpc->exitstatus = RPC_FAIL;
	brpc->rpc_error_ok = rpc_error_ok;
	brpc->resulttok = NULL;
	brpc->errortok = NULL;
	brpc->errorcode = 0;
	if (ctx) {
		/* Create child whose destructor will stop us calling */
		brpc->stopper = tal(ctx, struct bitcoin_rpc *);
		*brpc->stopper = brpc;
		tal_add_destructor(brpc->stopper, stop_process_brpc);
		tal_add_destructor(brpc, remove_stopper);
	} else
		brpc->stopper = NULL;

	brpc->cmd = tal_fmt(brpc, "%s ", cmd);
	brpc->request = tal_fmt(brpc,
				"{\"jsonrpc\": \"1.0\", \"id\":\"lightningd\", "
				"\"method\": \"%s\", \"params\":",
				cmd);

	tal_append_fmt(&brpc->request, "[ ");

	va_start(ap, cmd);
	arg = va_arg(ap, const char *);
	if (arg != NULL) {
		do {
			next_arg = va_arg(ap, const char *);
			if (next_arg != NULL)
				add_input(&brpc->request, arg, false);
			else
				add_input(&brpc->request, arg, true);
			tal_append_fmt(&brpc->cmd, " ");
			brpc->cmd = tal_strcat(brpc, take(brpc->cmd), arg);
			arg = next_arg;
		} while (arg != NULL);
	}
	tal_append_fmt(&brpc->request, "]}");
	va_end(ap);

	list_add_tail(&bitcoind->pending[brpc->prio], &brpc->list);
	next_brpc(bitcoind, brpc->prio);
	return brpc;
}

static bool extract_feerate(struct bitcoin_rpc *brpc, const char *output,
			    size_t output_bytes, u64 *feerate)
{
	const jsmntok_t *feeratetok;

	if (brpc->exitstatus != RPC_SUCCESS) {
		log_debug(brpc->bitcoind->log, "%s", brpc->cmd);
		return false;
	}

	feeratetok = json_get_member(brpc->output, brpc->resulttok, "feerate");
	if (!feeratetok)
		return false;

	return json_to_bitcoin_amount(output, feeratetok, feerate);
}

struct estimatefee {
	size_t i;
	const u32 *blocks;
	const char **estmode;

	void (*cb)(struct bitcoind *bitcoind, const u32 satoshi_per_kw[],
		   void *);
	void *arg;
	u32 *satoshi_per_kw;
};

static void do_one_estimatefee(struct bitcoind *bitcoind,
			       struct estimatefee *efee);

static bool process_estimatefee(struct bitcoin_rpc *brpc)
{
	u64 feerate;
	struct estimatefee *efee = brpc->cb_arg;

	/* FIXME: We could trawl recent blocks for median fee... */
	if (!extract_feerate(brpc, brpc->output, brpc->output_bytes,
			     &feerate)) {
		log_unusual(brpc->bitcoind->log, "Unable to estimate %s/%u fee",
			    efee->estmode[efee->i], efee->blocks[efee->i]);

#if DEVELOPER
		/* This is needed to test for failed feerate estimates
		 * in DEVELOPER mode */
		efee->satoshi_per_kw[efee->i] = 0;
#else
		/* If we are in testnet mode we want to allow payments
		 * with the minimal fee even if the estimate didn't
		 * work out. This is less disruptive than erring out
		 * all the time. */
		if (get_chainparams(brpc->bitcoind->ld)->testnet)
			efee->satoshi_per_kw[efee->i] = FEERATE_FLOOR;
		else
			efee->satoshi_per_kw[efee->i] = 0;
#endif
	} else
		/* Rate in satoshi per kw. */
		efee->satoshi_per_kw[efee->i] =
		    feerate_from_style(feerate, FEERATE_PER_KBYTE);

	efee->i++;
	if (efee->i == tal_count(efee->satoshi_per_kw)) {
		efee->cb(brpc->bitcoind, efee->satoshi_per_kw, efee->arg);
		tal_free(efee);
	} else {
		/* Next */
		do_one_estimatefee(brpc->bitcoind, efee);
	}
	return true;
}

static void do_one_estimatefee(struct bitcoind *bitcoind,
			       struct estimatefee *efee)
{
	char blockstr[STR_MAX_CHARS(u32)];

	snprintf(blockstr, sizeof(blockstr), "%u", efee->blocks[efee->i]);
	start_bitcoin_rpc(bitcoind, NULL, process_estimatefee, false,
			  BITCOIND_LOW_PRIO, NULL, efee, "estimatesmartfee",
			  blockstr, efee->estmode[efee->i], NULL);
}

void bitcoind_estimate_fees_(struct bitcoind *bitcoind, const u32 blocks[],
			     const char *estmode[], size_t num_estimates,
			     void (*cb)(struct bitcoind *bitcoind,
					const u32 satoshi_per_kw[], void *),
			     void *arg)
{
	struct estimatefee *efee = tal(bitcoind, struct estimatefee);

	efee->i = 0;
	efee->blocks = tal_dup_arr(efee, u32, blocks, num_estimates, 0);
	efee->estmode =
	    tal_dup_arr(efee, const char *, estmode, num_estimates, 0);
	efee->cb = cb;
	efee->arg = arg;
	efee->satoshi_per_kw = tal_arr(efee, u32, num_estimates);

	do_one_estimatefee(bitcoind, efee);
}

static bool process_sendrawtx(struct bitcoin_rpc *brpc)
{
	const jsmntok_t *msgtok;
	const char *msg;
	void (*cb)(struct bitcoind * bitcoind, int, const char *msg, void *) =
	    brpc->cb;

	if (brpc->exitstatus == RPC_ERROR) {
		msgtok =
		    json_get_member(brpc->output, brpc->errortok, "message");
		if (msgtok)
			msg = tal_strndup(brpc, brpc->output + msgtok->start,
					  msgtok->end - msgtok->start);
		else
			msg = tal_strndup(
			    brpc, brpc->output + brpc->errortok->start,
			    brpc->errortok->end - brpc->errortok->start);
	} else
		msg =
		    tal_strndup(brpc, brpc->output + brpc->resulttok->start,
				brpc->resulttok->end - brpc->resulttok->start);

	log_debug(brpc->bitcoind->log, "sendrawtx exit %u, gave %s",
		  brpc->exitstatus, msg);

	cb(brpc->bitcoind, brpc->exitstatus, msg, brpc->cb_arg);
	return true;
}

void bitcoind_sendrawtx_(struct bitcoind *bitcoind, const char *hextx,
			 void (*cb)(struct bitcoind *bitcoind, int exitstatus,
				    const char *msg, void *),
			 void *arg)
{
	log_debug(bitcoind->log, "sendrawtransaction: %s", hextx);
	start_bitcoin_rpc(bitcoind, NULL, process_sendrawtx, true,
			  BITCOIND_HIGH_PRIO, cb, arg, "sendrawtransaction",
			  hextx, NULL);
}

static bool process_rawblock(struct bitcoin_rpc *brpc)
{
	struct bitcoin_block *blk;
	void (*cb)(struct bitcoind * bitcoind, struct bitcoin_block * blk,
		   void *arg) = brpc->cb;

	int blklen = brpc->resulttok->end - brpc->resulttok->start;
	const char *blkhex =
	    tal_strndup(brpc, brpc->output + brpc->resulttok->start, blklen);

	blk = bitcoin_block_from_hex(brpc, (const char *)blkhex, blklen);
	if (!blk)
		fatal("%s: bad block '%.*s'?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);

	cb(brpc->bitcoind, blk, brpc->cb_arg);
	return true;
}

void bitcoind_getrawblock_(struct bitcoind *bitcoind,
			   const struct bitcoin_blkid *blockid,
			   void (*cb)(struct bitcoind *bitcoind,
				      struct bitcoin_block *blk, void *arg),
			   void *arg)
{
	char hex[hex_str_size(sizeof(*blockid))];

	bitcoin_blkid_to_hex(blockid, hex, sizeof(hex));
	start_bitcoin_rpc(bitcoind, NULL, process_rawblock, false,
			  BITCOIND_HIGH_PRIO, cb, arg, "getblock", hex, "false",
			  NULL);
}

static bool process_getblockcount(struct bitcoin_rpc *brpc)
{
	u32 blockcount;
	void (*cb)(struct bitcoind * bitcoind, u32 blockcount, void *arg) =
	    brpc->cb;

	if (!json_to_number(brpc->output, brpc->resulttok, &blockcount))
		fatal("%s: gave non-numeric blockcount %s", brpc->cmd,
		      brpc->output);

	cb(brpc->bitcoind, blockcount, brpc->cb_arg);
	return true;
}

void bitcoind_getblockcount_(struct bitcoind *bitcoind,
			     void (*cb)(struct bitcoind *bitcoind,
					u32 blockcount, void *arg),
			     void *arg)
{
	start_bitcoin_rpc(bitcoind, NULL, process_getblockcount, false,
			  BITCOIND_HIGH_PRIO, cb, arg, "getblockcount", NULL);
}

struct get_output {
	unsigned int blocknum, txnum, outnum;

	/* The real callback */
	void (*cb)(struct bitcoind *bitcoind,
		   const struct bitcoin_tx_output *txout, void *arg);

	/* The real callback arg */
	void *cbarg;
};

static void process_get_output(struct bitcoind *bitcoind,
			       const struct bitcoin_tx_output *txout, void *arg)
{
	struct get_output *go = arg;
	go->cb(bitcoind, txout, go->cbarg);
}

static bool process_gettxout(struct bitcoin_rpc *brpc)
{
	void (*cb)(struct bitcoind * bitcoind,
		   const struct bitcoin_tx_output *output, void *arg) =
	    brpc->cb;
	const jsmntok_t *tokens, *valuetok, *scriptpubkeytok, *hextok;
	struct bitcoin_tx_output out;

	/* As of at least v0.15.1.0, bitcoind returns "success" but an empty
	   string on a spent gettxout */
	if ((brpc->exitstatus != RPC_SUCCESS) || brpc->output_bytes == 0)  {
		log_debug(brpc->bitcoind->log, "%s: not unspent output?",
			  brpc->cmd);
		cb(brpc->bitcoind, NULL, brpc->cb_arg);
		return true;
	}

	tokens = brpc->resulttok;

	valuetok = json_get_member(brpc->output, tokens, "value");
	if (!valuetok)
		fatal("%s: had no value member (%.*s)?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);

	if (!json_to_bitcoin_amount(brpc->output, valuetok, &out.amount.satoshis)) /* Raw: talking to bitcoind */
		fatal("%s: had bad value (%.*s)?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);

	scriptpubkeytok = json_get_member(brpc->output, tokens, "scriptPubKey");
	if (!scriptpubkeytok)
		fatal("%s: had no scriptPubKey member (%.*s)?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);
	hextok = json_get_member(brpc->output, scriptpubkeytok, "hex");
	if (!hextok)
		fatal("%s: had no scriptPubKey->hex member (%.*s)?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);

	out.script = tal_hexdata(brpc, brpc->output + hextok->start,
				 hextok->end - hextok->start);
	if (!out.script)
		fatal("%s: scriptPubKey->hex invalid hex (%.*s)?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);

	cb(brpc->bitcoind, &out, brpc->cb_arg);
	return true;
}

/**
 * process_getblock -- Retrieve a block from bitcoind
 *
 * Used to resolve a `txoutput` after identifying the blockhash, and
 * before extracting the outpoint from the UTXO.
 */
static bool process_getblock(struct bitcoin_rpc *brpc)
{
	void (*cb)(struct bitcoind * bitcoind,
		   const struct bitcoin_tx_output *output, void *arg) =
	    brpc->cb;
	struct get_output *go = brpc->cb_arg;
	void *cbarg = go->cbarg;
	const jsmntok_t *txstok, *txidtok;
	struct bitcoin_txid txid;

	if (brpc->exitstatus != RPC_SUCCESS) {
		log_debug(brpc->bitcoind->log, "%s: error", brpc->cmd);
		cb(brpc->bitcoind, NULL, brpc->cb_arg);
		tal_free(go);
		return true;
	}

	/*  "tx": [
	    "1a7bb0f58a5d235d232deb61d9e2208dabe69848883677abe78e9291a00638e8",
	    "56a7e3468c16a4e21a4722370b41f522ad9dd8006c0e4e73c7d1c47f80eced94",
	    ...
	*/
	txstok = json_get_member(brpc->output, brpc->resulttok, "tx");
	if (!txstok)
		fatal("%s: had no tx member (%.*s)?", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);

	/* Now, this can certainly happen, if txnum too large. */
	txidtok = json_get_arr(txstok, go->txnum);
	if (!txidtok) {
		log_debug(brpc->bitcoind->log, "%s: no txnum %u", brpc->cmd,
			  go->txnum);
		cb(brpc->bitcoind, NULL, cbarg);
		tal_free(go);
		return true;
	}

	if (!bitcoin_txid_from_hex(brpc->output + txidtok->start,
				   txidtok->end - txidtok->start, &txid))
		fatal("%s: had bad txid (%.*s)?", brpc->cmd,
		      txidtok->end - txidtok->start,
		      brpc->output + txidtok->start);

	go->cb = cb;

	/* Now get the raw tx output. */
	bitcoind_gettxout(brpc->bitcoind, &txid, go->outnum, process_get_output,
			  go);
	return true;
}

static bool process_getblockhash_for_txout(struct bitcoin_rpc *brpc)
{
	void (*cb)(struct bitcoind * bitcoind,
		   const struct bitcoin_tx_output *output, void *arg) =
	    brpc->cb;
	struct get_output *go = brpc->cb_arg;
	const char *blockhash;

	if (brpc->exitstatus != RPC_SUCCESS) {
		void *cbarg = go->cbarg;
		log_debug(brpc->bitcoind->log, "%s: invalid blocknum?",
			  brpc->cmd);
		tal_free(go);
		cb(brpc->bitcoind, NULL, cbarg);
		return true;
	}

	blockhash = tal_strndup(brpc, brpc->output + brpc->resulttok->start,
				brpc->resulttok->end - brpc->resulttok->start);

	start_bitcoin_rpc(brpc->bitcoind, NULL, process_getblock, true,
			  BITCOIND_LOW_PRIO, cb, go, "getblock",
			  take(blockhash), NULL);
	return true;
}

void bitcoind_getoutput_(struct bitcoind *bitcoind, unsigned int blocknum,
			 unsigned int txnum, unsigned int outnum,
			 void (*cb)(struct bitcoind *bitcoind,
				    const struct bitcoin_tx_output *output,
				    void *arg),
			 void *arg)
{
	struct get_output *go = tal(bitcoind, struct get_output);
	go->blocknum = blocknum;
	go->txnum = txnum;
	go->outnum = outnum;
	go->cbarg = arg;

	/* We may not have topology ourselves that far back, so ask bitcoind */
	start_bitcoin_rpc(bitcoind, NULL, process_getblockhash_for_txout, true,
			  BITCOIND_LOW_PRIO, cb, go, "getblockhash",
			  take(tal_fmt(NULL, "%u", blocknum)), NULL);

	notleak(go);
}

static bool process_getblockhash(struct bitcoin_rpc *brpc)
{
	struct bitcoin_blkid blkid;
	void (*cb)(struct bitcoind * bitcoind,
		   const struct bitcoin_blkid *blkid, void *arg) = brpc->cb;

	/* If it failed with error RPC_INVALID_PARAMETER, call with NULL block.
	 */
	if (brpc->exitstatus == RPC_ERROR) {
		/* Other error means we have to retry. */
		if (brpc->errorcode != RPC_INVALID_PARAMETER)
			return false;
		cb(brpc->bitcoind, NULL, brpc->cb_arg);
		return true;
	} else if (brpc->exitstatus == RPC_FAIL)
		return true;

	int len = brpc->resulttok->end - brpc->resulttok->start;

	if (!bitcoin_blkid_from_hex(brpc->output + brpc->resulttok->start, len,
				    &blkid)) {
		fatal("%s: bad blockid '%.*s'", brpc->cmd,
		      (int)brpc->output_bytes, brpc->output);
	}

	cb(brpc->bitcoind, &blkid, brpc->cb_arg);
	return true;
}

void bitcoind_getblockhash_(struct bitcoind *bitcoind, u32 height,
			    void (*cb)(struct bitcoind *bitcoind,
				       const struct bitcoin_blkid *blkid,
				       void *arg),
			    void *arg)
{
	char str[STR_MAX_CHARS(height)];
	snprintf(str, sizeof(str), "%u", height);

	start_bitcoin_rpc(bitcoind, NULL, process_getblockhash, true,
			  BITCOIND_HIGH_PRIO, cb, arg, "getblockhash", str,
			  NULL);
}

void bitcoind_gettxout(struct bitcoind *bitcoind,
		       const struct bitcoin_txid *txid, const u32 outnum,
		       void (*cb)(struct bitcoind *bitcoind,
				  const struct bitcoin_tx_output *txout,
				  void *arg),
		       void *arg)
{
	start_bitcoin_rpc(bitcoind, NULL, process_gettxout, true,
			  BITCOIND_LOW_PRIO, cb, arg, "gettxout",
			  take(type_to_string(NULL, struct bitcoin_txid, txid)),
			  take(tal_fmt(NULL, "%u", outnum)), NULL);
}

/* Context for the getfilteredblock call. Wraps the actual arguments while we
 * process the various steps. */
struct filteredblock_call {
	struct list_node list;
	void (*cb)(struct bitcoind *bitcoind, const struct filteredblock *fb,
		   void *arg);
	void *arg;

	struct filteredblock *result;
	struct filteredblock_outpoint **outpoints;
	size_t current_outpoint;
	struct timeabs start_time;
	u32 height;
};

/* Declaration for recursion in process_getfilteredblock_step1 */
static void
process_getfiltered_block_final(struct bitcoind *bitcoind,
				const struct filteredblock_call *call);

static void
process_getfilteredblock_step3(struct bitcoind *bitcoind,
			       const struct bitcoin_tx_output *output,
			       void *arg)
{
	struct filteredblock_call *call = (struct filteredblock_call *)arg;
	struct filteredblock_outpoint *o = call->outpoints[call->current_outpoint];

	/* If this output is unspent, add it to the filteredblock result. */
	if (output)
		tal_arr_expand(&call->result->outpoints, tal_steal(call->result, o));

	call->current_outpoint++;
	if (call->current_outpoint < tal_count(call->outpoints)) {
		o = call->outpoints[call->current_outpoint];
		bitcoind_gettxout(bitcoind, &o->txid, o->outnum,
				  process_getfilteredblock_step3, call);
	} else {
		/* If there were no more outpoints to check, we call the callback. */
		process_getfiltered_block_final(bitcoind, call);
	}
}

static void process_getfilteredblock_step2(struct bitcoind *bitcoind,
					   struct bitcoin_block *block,
					   struct filteredblock_call *call)
{
	struct filteredblock_outpoint *o;
	struct bitcoin_tx *tx;

	/* If for some reason we couldn't get the block, just report a
	 * failure. */
	if (block == NULL)
		return process_getfiltered_block_final(bitcoind, call);

	call->result->prev_hash = block->hdr.prev_hash;

	/* Allocate an array containing all the potentially interesting
	 * outpoints. We will later copy the ones we're interested in into the
	 * call->result if they are unspent. */

	call->outpoints = tal_arr(call, struct filteredblock_outpoint *, 0);
	for (size_t i = 0; i < tal_count(block->tx); i++) {
		tx = block->tx[i];
		for (size_t j = 0; j < tx->wtx->num_outputs; j++) {
			const u8 *script = bitcoin_tx_output_get_script(NULL, tx, j);
			struct amount_asset amount = bitcoin_tx_output_get_amount(tx, j);
			if (amount_asset_is_main(&amount) && is_p2wsh(script, NULL)) {
				/* This is an interesting output, remember it. */
				o = tal(call->outpoints, struct filteredblock_outpoint);
				bitcoin_txid(tx, &o->txid);
				o->amount = amount_asset_to_sat(&amount);
				o->txindex = i;
				o->outnum = j;
				o->scriptPubKey = tal_steal(o, script);
				tal_arr_expand(&call->outpoints, o);
			} else {
				tal_free(script);
			}
		}
	}

	if (tal_count(call->outpoints) == 0) {
		/* If there were no outpoints to check, we can short-circuit
		 * and just call the callback. */
		process_getfiltered_block_final(bitcoind, call);
	} else {

		/* Otherwise we start iterating through call->outpoints and
		 * store the one's that are unspent in
		 * call->result->outpoints. */
		o = call->outpoints[call->current_outpoint];
		bitcoind_gettxout(bitcoind, &o->txid, o->outnum,
				  process_getfilteredblock_step3, call);
	}
}

static void process_getfilteredblock_step1(struct bitcoind *bitcoind,
					   const struct bitcoin_blkid *blkid,
					   struct filteredblock_call *call)
{
	/* If we were unable to fetch the block hash (bitcoind doesn't know
	 * about a block at that height), we can short-circuit and just call
	 * the callback. */
	if (!blkid)
		return process_getfiltered_block_final(bitcoind, call);

	/* So we have the first piece of the puzzle, the block hash */
	call->result = tal(call, struct filteredblock);
	call->result->height = call->height;
	call->result->outpoints = tal_arr(call->result, struct filteredblock_outpoint *, 0);
	call->result->id = *blkid;

	/* Now get the raw block to get all outpoints that were created in
	 * this block. */
	bitcoind_getrawblock(bitcoind, blkid, process_getfilteredblock_step2, call);
}

/* Takes a call, dispatches it to all queued requests that match the same
 * height, and then kicks off the next call. */
static void
process_getfiltered_block_final(struct bitcoind *bitcoind,
				const struct filteredblock_call *call)
{
	struct filteredblock_call *c, *next;
	u32 height = call->height;

	if (call->result == NULL)
		goto next;

	/* Need to steal so we don't accidentally free it while iterating through the list below. */
	struct filteredblock *fb = tal_steal(NULL, call->result);
	list_for_each_safe(&bitcoind->pending_getfilteredblock, c, next, list) {
		if (c->height == height) {
			c->cb(bitcoind, fb, c->arg);
			list_del(&c->list);
			tal_free(c);
		}
	}
	tal_free(fb);

next:
	/* Nothing to free here, since `*call` was already deleted during the
	 * iteration above. It was also removed from the list, so no need to
	 * pop here. */
	if (!list_empty(&bitcoind->pending_getfilteredblock)) {
		c = list_top(&bitcoind->pending_getfilteredblock, struct filteredblock_call, list);
		bitcoind_getblockhash(bitcoind, c->height, process_getfilteredblock_step1, c);
	}
}

void bitcoind_getfilteredblock_(struct bitcoind *bitcoind, u32 height,
				void (*cb)(struct bitcoind *bitcoind,
					   const struct filteredblock *fb,
					   void *arg),
				void *arg)
{
	/* Stash the call context for when we need to call the callback after
	 * all the bitcoind calls we need to perform. */
	struct filteredblock_call *call = tal(bitcoind, struct filteredblock_call);
	/* If this is the first request, we should start processing it. */
	bool start = list_empty(&bitcoind->pending_getfilteredblock);
	call->cb = cb;
	call->arg = arg;
	call->height = height;
	assert(call->cb != NULL);
	call->start_time = time_now();
	call->result = NULL;
	call->current_outpoint = 0;

	list_add_tail(&bitcoind->pending_getfilteredblock, &call->list);
	if (start)
		bitcoind_getblockhash(bitcoind, height, process_getfilteredblock_step1, call);
}

static bool extract_numeric_version(struct bitcoin_cli *bcli,
			    const char *output, size_t output_bytes,
			    u64 *version)
{
	const jsmntok_t *tokens, *versiontok;
	bool valid;

	tokens = json_parse_input(output, output, output_bytes, &valid);
	if (!tokens)
		fatal("%s: %s response",
		      bcli_args(tmpctx, bcli),
		      valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_OBJECT) {
		log_unusual(bcli->bitcoind->log,
			    "%s: gave non-object (%.*s)?",
			    bcli_args(tmpctx, bcli),
			    (int)output_bytes, output);
		return false;
	}

	versiontok = json_get_member(output, tokens, "version");
	if (!versiontok)
		return false;

	return json_to_u64(output, versiontok, version);
}

static bool process_getclientversion(struct bitcoin_cli *bcli)
{
	u64 version;
	u64 min_version = bcli->bitcoind->chainparams->cli_min_supported_version;

	if (!extract_numeric_version(bcli, bcli->output,
				     bcli->output_bytes,
				     &version)) {
		fatal("%s: Unable to getclientversion (%.*s)",
		      bcli_args(tmpctx, bcli),
		      (int)bcli->output_bytes,
		      bcli->output);
	}

	if (version < min_version)
		fatal("Unsupported bitcoind version? bitcoind version: %"PRIu64","
		      " supported minimum version: %"PRIu64"",
		      version, min_version);

	return true;
}

void bitcoind_getclientversion(struct bitcoind *bitcoind)
{
	/* `getnetworkinfo` was added in v0.14.0. The older version would
	 * return non-zero exitstatus. */
	start_bitcoin_cli(bitcoind, NULL, process_getclientversion, false,
			  BITCOIND_HIGH_PRIO,
			  NULL, NULL,
			  "getnetworkinfo", NULL);
}

/* Mutual recursion */
static bool process_getblockchaininfo(struct bitcoin_cli *bcli);

static void retry_getblockchaininfo(struct bitcoind *bitcoind)
{
	assert(!bitcoind->synced);
	start_bitcoin_cli(bitcoind, NULL,
			  process_getblockchaininfo,
			  false, BITCOIND_LOW_PRIO, NULL, NULL,
			  "getblockchaininfo", NULL);
}

/* Given JSON object from getblockchaininfo, are we synced?  Poll if not. */
static void is_bitcoind_synced_yet(struct bitcoind *bitcoind,
				   const char *output, size_t output_len,
				   const jsmntok_t *obj,
				   bool initial)
{
	const jsmntok_t *t;
	unsigned int headers, blocks;
	bool ibd;

	t = json_get_member(output, obj, "headers");
	if (!t || !json_to_number(output, t, &headers))
		fatal("Invalid 'headers' field in getblockchaininfo '%.*s'",
		      (int)output_len, output);

	t = json_get_member(output, obj, "blocks");
	if (!t || !json_to_number(output, t, &blocks))
		fatal("Invalid 'blocks' field in getblockchaininfo '%.*s'",
		      (int)output_len, output);

	t = json_get_member(output, obj, "initialblockdownload");
	if (!t || !json_to_bool(output, t, &ibd))
		fatal("Invalid 'initialblockdownload' field in getblockchaininfo '%.*s'",
		      (int)output_len, output);

	if (ibd) {
		if (initial)
			log_unusual(bitcoind->log,
				    "Waiting for initial block download"
				    " (this can take a while!)");
		else
			log_debug(bitcoind->log,
				  "Still waiting for initial block download");
	} else if (headers != blocks) {
		if (initial)
			log_unusual(bitcoind->log,
				    "Waiting for bitcoind to catch up"
				    " (%u blocks of %u)",
				    blocks, headers);
		else
			log_debug(bitcoind->log,
				  "Waiting for bitcoind to catch up"
				  " (%u blocks of %u)",
				  blocks, headers);
	} else {
		if (!initial)
			log_info(bitcoind->log, "Bitcoind now synced.");
		bitcoind->synced = true;
		return;
	}

	bitcoind->synced = false;
	notleak(new_reltimer(bitcoind->ld->timers, bitcoind,
			     /* Be 4x more aggressive in this case. */
			     time_divide(time_from_sec(bitcoind->ld->topology
						       ->poll_seconds), 4),
			     retry_getblockchaininfo, bitcoind));
}

static bool process_getblockchaininfo(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens;
	bool valid;

	tokens = json_parse_input(bcli, bcli->output, bcli->output_bytes,
				  &valid);
	if (!tokens)
		fatal("%s: %s response (%.*s)",
		      bcli_args(tmpctx, bcli),
		      valid ? "partial" : "invalid",
		      (int)bcli->output_bytes, bcli->output);

	if (tokens[0].type != JSMN_OBJECT) {
		log_unusual(bcli->bitcoind->log,
			    "%s: gave non-object (%.*s)?",
			    bcli_args(tmpctx, bcli),
			    (int)bcli->output_bytes, bcli->output);
		return false;
	}

	is_bitcoind_synced_yet(bcli->bitcoind, bcli->output, bcli->output_bytes,
			       tokens, false);
	return true;
}

static void destroy_bitcoind(struct bitcoind *bitcoind)
{
	/* Suppresses the callbacks from brpc_finished as we free conns. */
	bitcoind->shutdown = true;
}

static void fatal_bitcoind_failure(struct bitcoind *bitcoind,
				   const char *error_message)
{
	fprintf(stderr, "%s\n\n", error_message);
	fprintf(stderr,
		"Make sure you have bitcoind running and that bitcoin rpc is "
		"able to connect to bitcoind.\n\n");
	fprintf(stderr,
		"You can verify that your Bitcoin Core installation is ready "
		"for use by running:\n\n");
	fprintf(stderr,
		"curl --user %s --data-binary '{\"jsonrpc\": \"1.0\","
		"\"id\":\"lightning\", \"method\": \"getblockchaininfo\","
		"\"params\": [] }' -H 'content-type: text/plain;' "
		"http://%s:%d/\n",
		bitcoind->rpcuser, bitcoind->rpcconnect, bitcoind->rpcport);
	exit(1);
}

/* This function is used to check "chain" field from
 * bitcoin-cli "getblockchaininfo" API */
static char* check_blockchain_from_bitcoincli(const tal_t *ctx,
				struct bitcoind *bitcoind,
				char* output, const char **cmd)
{
	size_t output_bytes;
	const jsmntok_t *tokens, *valuetok;
	bool valid;

	if (!output)
		return tal_fmt(ctx, "Reading from %s failed: %s",
			       bcli_args_direct(tmpctx, cmd), strerror(errno));

	output_bytes = tal_count(output);

	tokens = json_parse_input(cmd, output, output_bytes,
			          &valid);

	if (!tokens)
		return tal_fmt(ctx, "%s: %s response",
			       bcli_args_direct(tmpctx, cmd),
			       valid ? "partial" : "invalid");

	if (tokens[0].type != JSMN_OBJECT)
		return tal_fmt(ctx, "%s: gave non-object (%.*s)?",
			       bcli_args_direct(tmpctx, cmd),
			       (int)output_bytes, output);

	valuetok = json_get_member(output, tokens, "chain");
	if (!valuetok)
		return tal_fmt(ctx, "%s: had no chain member (%.*s)?",
			       bcli_args_direct(tmpctx, cmd),
			       (int)output_bytes, output);

	if(!json_tok_streq(output, valuetok,
			   bitcoind->chainparams->bip70_name))
		return tal_fmt(ctx, "Error blockchain for bitcoin-cli?"
			       " Should be: %s",
			       bitcoind->chainparams->bip70_name);

	is_bitcoind_synced_yet(bitcoind, output, output_bytes, tokens, true);
	return NULL;
}

void wait_for_bitcoind(struct bitcoind *bitcoind)
{
	struct bitcoin_rpc *brpc = tal(NULL, struct bitcoin_rpc);

	if ((bitcoind->rpccookiefile == NULL) &&
	    ((bitcoind->rpcuser == NULL) || (bitcoind->rpcpass == NULL) ||
	     (bitcoind->rpcconnect == NULL) || (bitcoind->rpcport == 0)))
		fatal("RPC server is not config,  See:\n"
		      " --bitcoin-rpcuser\n"
		      " --bitcoin-rpcpassword\n"
		      " --bitcoin-rpcconnect\n"
		      " --bitcoin-rpcport\n"
		      " --bitcoin-rpccookiefile\n");

	brpc->bitcoind = bitcoind;

	init_rpc_header(bitcoind);

	for (;;) {
		brpc->exitstatus = RPC_FAIL;
		brpc->errorcode = 0;
		brpc->start = time_now();
		brpc->prio = BITCOIND_HIGH_PRIO;
		brpc->process = NULL;

		brpc->request =
		    "{\"jsonrpc\": \"1.0\", \"id\":\"lightningd\", \"method\": "
		    "\"getblockchaininfo\", \"params\":[] }";

		if (!rpc_request(brpc))
			fatal_bitcoind_failure(bitcoind, "RPC call fail\n");

		bitcoind->num_requests[BITCOIND_HIGH_PRIO]++;

		brpc->output = tal_arr(brpc, char, 100);
		brpc->output_bytes = 0;
		int ret = 0;
		do {
			ret =
			    read(brpc->fd, brpc->output + brpc->output_bytes,
				 tal_count(brpc->output) - brpc->output_bytes);
			if (ret < 0)
				fatal_bitcoind_failure(bitcoind,
						       "RPC call fail\n");
			else if (ret == 0) {
				brpc->output_bytes += ret;
				break;
			} else {
				brpc->output_bytes += ret;
				tal_resize(&brpc->output,
					   brpc->output_bytes * 2);
			}
		} while (ret);

		handle_http_response(brpc->output, brpc);

		if (brpc->exitstatus == RPC_SUCCESS)
			break;
		}

		else if (brpc->exitstatus == RPC_FAIL)
			fatal_bitcoind_failure(bitcoind, brpc->output);

		/* Client still warming up */
		else if (brpc->errorcode == RPC_IN_WARMUP) {
			log_unusual(bitcoind->log,
				    "Waiting for bitcoind to warm up...");
		} else if (brpc->errorcode == RPC_CLIENT_IN_INITIAL_DOWNLOAD) {
			log_unusual(bitcoind->log,
				    "Waiting for bitcoind downloading initial "
				    "blocks...");
		} else if (brpc->output)
			fatal_bitcoind_failure(bitcoind, brpc->output);

		sleep(1);
	}

	bitcoind->num_requests[BITCOIND_HIGH_PRIO]--;
	tal_free(brpc->output);
	tal_free(brpc);
}

struct bitcoind *new_bitcoind(const tal_t *ctx, struct lightningd *ld,
			      struct log *log)
{
	struct bitcoind *bitcoind = tal(ctx, struct bitcoind);

	/* Use testnet by default, change later if we want another network */
	bitcoind->chainparams = chainparams_for_network("testnet");
	bitcoind->datadir = NULL;
	bitcoind->ld = ld;
	bitcoind->log = log;
	for (size_t i = 0; i < BITCOIND_NUM_PRIO; i++) {
		bitcoind->num_requests[i] = 0;
		list_head_init(&bitcoind->pending[i]);
	}
	list_head_init(&bitcoind->pending_getfilteredblock);
	bitcoind->shutdown = false;
	bitcoind->error_count = 0;
	bitcoind->retry_timeout = 60;
	bitcoind->rpccookiefile = NULL;
	bitcoind->rpcuser = NULL;
	bitcoind->rpcpass = NULL;
	bitcoind->rpcconnect = tal_fmt(bitcoind, DEFAULT_RPCCONNECT);
	bitcoind->rpcport = bitcoind->chainparams->rpc_port;
	bitcoind->rpcclienttimeout = DEFAULT_HTTP_CLIENT_TIMEOUT;
	bitcoind->rpcthreads = BITCOIND_MAX_PARALLEL;

	tal_add_destructor(bitcoind, destroy_bitcoind);

	return bitcoind;
} 

static const struct plugin_command commands[] = { {
		"sendrawtx",
		"sendrawtx",
		"Send payment specified by {bolt11} with {amount}",
		"Try to send a payment, retrying {retry_for} seconds before giving up",
		json_pay
	}, {
		"estimatefee",
		"estimatefee",
		"Detail status of attempts to pay {bolt11}, or all",
		"Covers both old payments and current ones.",
		json_paystatus
	}, {
		"estimatefee",
		"estimatefee",
		"Detail status of attempts to pay {bolt11}, or all",
		"Covers both old payments and current ones.",
		json_paystatus
	}, {
		"get_output",
		"get_output",
		"Detail status of attempts to pay {bolt11}, or all",
		"Covers both old payments and current ones.",
		json_paystatus
	}, {
		"getfilteredblock",
		"getfilteredblock",
		"Detail status of attempts to pay {bolt11}, or all",
		"Covers both old payments and current ones.",
		json_paystatus
	}, {
		"getblockcount",
		"getblockcount",
		"List result of payment {bolt11}, or all",
		"Covers old payments (failed and succeeded) and current ones.",
		json_listpays
	}
};

int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, commands, ARRAY_SIZE(commands), NULL);
}
