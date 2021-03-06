#ifndef LIGHTNING_LIGHTNINGD_CHANNEL_H
#define LIGHTNING_LIGHTNINGD_CHANNEL_H
#include "config.h"
#include <ccan/list/list.h>
#include <lightningd/channel_state.h>
#include <lightningd/peer_htlcs.h>
#include <wallet/wallet.h>

struct uncommitted_channel;

struct channel {
	/* Inside peer->channels. */
	struct list_node list;

	/* Peer context */
	struct peer *peer;

	/* Database ID: 0 == not in db yet */
	u64 dbid;

	/* Error message (iff in error state) */
	u8 *error;

	/* Their shachain. */
	struct wallet_shachain their_shachain;

 	/* What's happening. */
 	enum channel_state state;

	/* Which side offered channel? */
	enum side funder;

	/* Is there a single subdaemon responsible for us? */
	struct subd *owner;

	/* History */
	struct log *log;

	/* Channel flags from opening message. */
	u8 channel_flags;

	/* Our channel config. */
	struct channel_config our_config;

	/* Minimum funding depth (specified by us if they fund). */
	u32 minimum_depth;

	/* Tracking commitment transaction numbers. */
	u64 next_index[NUM_SIDES];
	u64 next_htlc_id;

	/* Funding txid and amounts */
	struct bitcoin_txid funding_txid;
	u16 funding_outnum;
	u64 funding_satoshi, push_msat;
	bool remote_funding_locked;
	/* Channel if locked locally. */
	struct short_channel_id *scid;

	/* Amount going to us, not counting unfinished HTLCs; if we have one. */
	u64 our_msatoshi;

	/* Last tx they gave us. */
	struct bitcoin_tx *last_tx;
	secp256k1_ecdsa_signature last_sig;
	secp256k1_ecdsa_signature *last_htlc_sigs;

	/* Keys for channel */
	struct channel_info channel_info;

	/* Secret seed (FIXME: Move to hsm!) */
	struct privkey seed;

	/* Their scriptpubkey if they sent shutdown. */
	u8 *remote_shutdown_scriptpubkey;
	/* Our key for shutdown (-1 if not chosen yet) */
	s64 local_shutdown_idx;

	/* Reestablishment stuff: last sent commit and revocation details. */
	bool last_was_revoke;
	struct changed_htlc *last_sent_commit;

	/* Blockheight at creation, scans for funding confirmations
	 * will start here */
	u64 first_blocknum;
};

struct channel *new_channel(struct peer *peer, u64 dbid,
			    /* NULL or stolen */
			    struct wallet_shachain *their_shachain,
			    enum channel_state state,
			    enum side funder,
			    /* NULL or stolen */
			    struct log *log,
			    u8 channel_flags,
			    const struct channel_config *our_config,
			    u32 minimum_depth,
			    u64 next_index_local,
			    u64 next_index_remote,
			    u64 next_htlc_id,
			    const struct bitcoin_txid *funding_txid,
			    u16 funding_outnum,
			    u64 funding_satoshi,
			    u64 push_msat,
			    bool remote_funding_locked,
			    /* NULL or stolen */
			    struct short_channel_id *scid,
			    u64 our_msatoshi,
			    /* Stolen */
			    struct bitcoin_tx *last_tx,
			    const secp256k1_ecdsa_signature *last_sig,
			    /* NULL or stolen */
			    secp256k1_ecdsa_signature *last_htlc_sigs,
			    const struct channel_info *channel_info,
			    /* NULL or stolen */
			    u8 *remote_shutdown_scriptpubkey,
			    /* (-1 if not chosen yet) */
			    s64 local_shutdown_idx,
			    bool last_was_revoke,
			    /* NULL or stolen */
			    struct changed_htlc *last_sent_commit,
			    u32 first_blocknum);

void delete_channel(struct channel *channel);

const char *channel_state_name(const struct channel *channel);
const char *channel_state_str(enum channel_state state);

void channel_set_owner(struct channel *channel, struct subd *owner);

/* Channel has failed, but can try again. */
PRINTF_FMT(2,3) void channel_fail_transient(struct channel *channel,
					    const char *fmt,...);
/* Channel has failed, give up on it. */
void channel_fail_permanent(struct channel *channel, const char *fmt, ...);
/* Permanent error, but due to internal problems, not peer. */
void channel_internal_error(struct channel *channel, const char *fmt, ...);

void channel_set_state(struct channel *channel,
		       enum channel_state old_state,
		       enum channel_state state);

/* Find a channel which is not onchain, if any */
struct channel *peer_active_channel(struct peer *peer);

/* Get active channel for peer, optionally any uncommitted_channel. */
struct channel *active_channel_by_id(struct lightningd *ld,
				     const struct pubkey *id,
				     struct uncommitted_channel **uc);

void channel_set_last_tx(struct channel *channel,
			 struct bitcoin_tx *tx,
			 const secp256k1_ecdsa_signature *sig);

static inline bool channel_can_add_htlc(const struct channel *channel)
{
	return channel->state == CHANNELD_NORMAL;
}

static inline bool channel_fees_can_change(const struct channel *channel)
{
	return channel->state == CHANNELD_NORMAL
		|| channel->state == CHANNELD_SHUTTING_DOWN;
}

static inline bool channel_can_remove_htlc(const struct channel *channel)
{
	return channel->state == CHANNELD_NORMAL
		|| channel->state == CHANNELD_SHUTTING_DOWN
		|| channel->state == ONCHAIND_THEIR_UNILATERAL
		|| channel->state == ONCHAIND_OUR_UNILATERAL;
}

static inline bool channel_state_on_chain(enum channel_state state)
{
	return state == ONCHAIND_CHEATED
		|| state == ONCHAIND_THEIR_UNILATERAL
		|| state == ONCHAIND_OUR_UNILATERAL
		|| state == ONCHAIND_MUTUAL;
}

static inline bool channel_on_chain(const struct channel *channel)
{
	return channel_state_on_chain(channel->state);
}

static inline bool channel_active(const struct channel *channel)
{
	return channel->state != FUNDING_SPEND_SEEN
		&& channel->state != CLOSINGD_COMPLETE
		&& !channel_on_chain(channel);
}

static inline bool channel_wants_reconnect(const struct channel *channel)
{
	return channel->state <= CLOSINGD_COMPLETE;
}

void derive_channel_seed(struct lightningd *ld, struct privkey *seed,
			 const struct pubkey *peer_id,
			 const u64 dbid);
#endif /* LIGHTNING_LIGHTNINGD_CHANNEL_H */
