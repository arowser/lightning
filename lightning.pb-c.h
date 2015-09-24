/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: lightning.proto */

#ifndef PROTOBUF_C_lightning_2eproto__INCLUDED
#define PROTOBUF_C_lightning_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1001001 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _Sha256Hash Sha256Hash;
typedef struct _Signature Signature;
typedef struct _Locktime Locktime;
typedef struct _BitcoinPubkey BitcoinPubkey;
typedef struct _Funding Funding;
typedef struct _OpenChannel OpenChannel;
typedef struct _OpenAnchor OpenAnchor;
typedef struct _OpenCommitSig OpenCommitSig;
typedef struct _OpenComplete OpenComplete;
typedef struct _Update Update;
typedef struct _UpdateAddHtlc UpdateAddHtlc;
typedef struct _UpdateDeclineHtlc UpdateDeclineHtlc;
typedef struct _UpdateCompleteHtlc UpdateCompleteHtlc;
typedef struct _UpdateTimedoutHtlc UpdateTimedoutHtlc;
typedef struct _UpdateRoutefailHtlc UpdateRoutefailHtlc;
typedef struct _UpdateAccept UpdateAccept;
typedef struct _UpdateSignature UpdateSignature;
typedef struct _UpdateComplete UpdateComplete;
typedef struct _CloseChannel CloseChannel;
typedef struct _CloseChannelComplete CloseChannelComplete;
typedef struct _CloseChannelAck CloseChannelAck;
typedef struct _Error Error;
typedef struct _Pkt Pkt;


/* --- enums --- */

typedef enum _OpenChannel__AnchorOffer {
  /*
   * I will create the anchor
   */
  OPEN_CHANNEL__ANCHOR_OFFER__WILL_CREATE_ANCHOR = 1,
  /*
   * I won't create the anchor
   */
  OPEN_CHANNEL__ANCHOR_OFFER__WONT_CREATE_ANCHOR = 2
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(OPEN_CHANNEL__ANCHOR_OFFER)
} OpenChannel__AnchorOffer;

/* --- messages --- */

/*
 * Protobufs don't have fixed-length fields, so these are a hack.
 */
struct  _Sha256Hash
{
  ProtobufCMessage base;
  uint64_t a;
  uint64_t b;
  uint64_t c;
  uint64_t d;
};
#define SHA256_HASH__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&sha256_hash__descriptor) \
    , 0, 0, 0, 0 }


struct  _Signature
{
  ProtobufCMessage base;
  uint64_t r1;
  uint64_t r2;
  uint64_t r3;
  uint64_t r4;
  uint64_t s1;
  uint64_t s2;
  uint64_t s3;
  uint64_t s4;
};
#define SIGNATURE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&signature__descriptor) \
    , 0, 0, 0, 0, 0, 0, 0, 0 }


typedef enum {
  LOCKTIME__LOCKTIME__NOT_SET = 0,
  LOCKTIME__LOCKTIME_SECONDS = 1,
  LOCKTIME__LOCKTIME_BLOCKS = 2,
} Locktime__LocktimeCase;

struct  _Locktime
{
  ProtobufCMessage base;
  Locktime__LocktimeCase locktime_case;
  union {
    uint32_t seconds;
    uint32_t blocks;
  };
};
#define LOCKTIME__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&locktime__descriptor) \
    , LOCKTIME__LOCKTIME__NOT_SET, {} }


/*
 * Pubkey for commitment transaction input.
 */
struct  _BitcoinPubkey
{
  ProtobufCMessage base;
  /*
   * Either 65 or 33 bytes.
   */
  ProtobufCBinaryData key;
};
#define BITCOIN_PUBKEY__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&bitcoin_pubkey__descriptor) \
    , {0,NULL} }


/*
 * How much a node charges (or pays!) for sending.
 */
struct  _Funding
{
  ProtobufCMessage base;
  /*
   * Base amount (in satoshi).
   */
  protobuf_c_boolean has_fixed;
  int64_t fixed;
  /*
   * This is charge per millionth of a satoshi.
   */
  protobuf_c_boolean has_per_micro_satoshi;
  int32_t per_micro_satoshi;
};
#define FUNDING__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&funding__descriptor) \
    , 0,0ll, 0,0 }


/*
 * Set channel params.
 */
struct  _OpenChannel
{
  ProtobufCMessage base;
  /*
   * Relative locktime for outputs going to us.
   */
  Locktime *delay;
  /*
   * Hash for revoking first commitment transaction.
   */
  Sha256Hash *revocation_hash;
  /*
   * Pubkey for anchor to pay into commitment tx.
   */
  BitcoinPubkey *commit_key;
  /*
   * How to pay money to us from commit_tx.
   */
  BitcoinPubkey *final_key;
  OpenChannel__AnchorOffer anch;
  /*
   * How far must anchor be buried before we consider channel live?
   */
  protobuf_c_boolean has_min_depth;
  uint32_t min_depth;
  /*
   * How much fee would I like on commitment tx?
   */
  uint64_t commitment_fee;
};
#define OPEN_CHANNEL__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&open_channel__descriptor) \
    , NULL, NULL, NULL, NULL, 0, 0,0u, 0 }


/*
 * Whoever is supplying anchor sends this.
 */
struct  _OpenAnchor
{
  ProtobufCMessage base;
  /*
   * Transaction ID of anchor.
   */
  Sha256Hash *txid;
  /*
   * Which output is going to the 2 of 2.
   */
  uint32_t output_index;
  /*
   * Amount of anchor output.
   */
  uint64_t amount;
  /*
   * Signature for your initial commitment tx.
   */
  Signature *commit_sig;
};
#define OPEN_ANCHOR__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&open_anchor__descriptor) \
    , NULL, 0, 0, NULL }


/*
 * Reply: signature for your initial commitment tx
 */
struct  _OpenCommitSig
{
  ProtobufCMessage base;
  Signature *sig;
};
#define OPEN_COMMIT_SIG__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&open_commit_sig__descriptor) \
    , NULL }


/*
 * Indicates we've seen anchor reach min-depth.
 */
struct  _OpenComplete
{
  ProtobufCMessage base;
  /*
   * Block it went into.
   */
  /*
   * FIXME: add a merkle proof plus block headers here?
   */
  Sha256Hash *blockid;
};
#define OPEN_COMPLETE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&open_complete__descriptor) \
    , NULL }


/*
 * Let's spend some money in the channel!
 */
struct  _Update
{
  ProtobufCMessage base;
  /*
   * Hash for which I will supply preimage to revoke this.
   */
  Sha256Hash *revocation_hash;
  /*
   * Change in current payment to-me (implies reverse to-you).
   */
  int64_t delta_msat;
};
#define UPDATE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&update__descriptor) \
    , NULL, 0 }


/*
 * Start a new commitment tx to add an HTLC me -> you.
 */
struct  _UpdateAddHtlc
{
  ProtobufCMessage base;
  /*
   * Hash for which I will supply preimage to revoke this commitment tx.
   */
  Sha256Hash *revocation_hash;
  /*
   * Amount for htlc (millisatoshi)
   */
  uint32_t amount_msat;
  /*
   * Hash for HTLC R value.
   */
  Sha256Hash *r_hash;
  /*
   * Time at which HTLC expires (absolute)
   */
  /*
   * FIXME: Routing information.
   */
  Locktime *expiry;
};
#define UPDATE_ADD_HTLC__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&update_add_htlc__descriptor) \
    , NULL, 0, NULL, NULL }


typedef enum {
  UPDATE_DECLINE_HTLC__REASON__NOT_SET = 0,
  UPDATE_DECLINE_HTLC__REASON_INSUFFICIENT_FUNDS = 1,
  UPDATE_DECLINE_HTLC__REASON_CANNOT_ROUTE = 2,
} UpdateDeclineHtlc__ReasonCase;

/*
 * We can't do this HTLC, sorry (instead of update_accept)
 */
struct  _UpdateDeclineHtlc
{
  ProtobufCMessage base;
  UpdateDeclineHtlc__ReasonCase reason_case;
  union {
    Funding *insufficient_funds;
    protobuf_c_boolean cannot_route;
  };
};
#define UPDATE_DECLINE_HTLC__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&update_decline_htlc__descriptor) \
    , UPDATE_DECLINE_HTLC__REASON__NOT_SET, {} }


/*
 * Complete your HTLC: I have the R value, pay me!
 */
struct  _UpdateCompleteHtlc
{
  ProtobufCMessage base;
  /*
   * Hash for which I will supply preimage to revoke this commitment tx.
   */
  Sha256Hash *revocation_hash;
  /*
   * HTLC R value.
   */
  Sha256Hash *r;
};
#define UPDATE_COMPLETE_HTLC__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&update_complete_htlc__descriptor) \
    , NULL, NULL }


/*
 * Remove my HTLC: it has timed out, before you got the R value.
 */
struct  _UpdateTimedoutHtlc
{
  ProtobufCMessage base;
  /*
   * Hash for which I will supply preimage to revoke this commitment tx.
   */
  Sha256Hash *revocation_hash;
  /*
   * Hash for HTLC R value.
   */
  Sha256Hash *r_hash;
};
#define UPDATE_TIMEDOUT_HTLC__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&update_timedout_htlc__descriptor) \
    , NULL, NULL }


/*
 * Remove your HTLC: routing has failed upstream
 */
struct  _UpdateRoutefailHtlc
{
  ProtobufCMessage base;
  /*
   * Hash for which I will supply preimage to revoke this commitment tx.
   */
  Sha256Hash *revocation_hash;
  /*
   * Hash for HTLC R value.
   */
  Sha256Hash *r_hash;
};
#define UPDATE_ROUTEFAIL_HTLC__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&update_routefail_htlc__descriptor) \
    , NULL, NULL }


/*
 * OK, I accept that update; here's your signature.
 */
struct  _UpdateAccept
{
  ProtobufCMessage base;
  /*
   * Signature for your new commitment tx.
   */
  Signature *sig;
  /*
   * Hash for which I will supply preimage to revoke this new commit tx.
   */
  Sha256Hash *revocation_hash;
};
#define UPDATE_ACCEPT__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&update_accept__descriptor) \
    , NULL, NULL }


/*
 * Thanks for accepting, here's my last bit.
 */
struct  _UpdateSignature
{
  ProtobufCMessage base;
  /*
   * Signature for your new commitment tx.
   */
  Signature *sig;
  /*
   * Hash preimage which revokes old commitment tx.
   */
  Sha256Hash *revocation_preimage;
};
#define UPDATE_SIGNATURE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&update_signature__descriptor) \
    , NULL, NULL }


/*
 * Complete the update.
 */
struct  _UpdateComplete
{
  ProtobufCMessage base;
  /*
   * Hash preimage which revokes old commitment tx.
   */
  Sha256Hash *revocation_preimage;
};
#define UPDATE_COMPLETE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&update_complete__descriptor) \
    , NULL }


/*
 * Begin cooperative close of channel.
 */
struct  _CloseChannel
{
  ProtobufCMessage base;
  /*
   * This is our signature a new transaction which spends the anchor
   * output to my open->final and your open->final,
   * as per the last commit tx.
   */
  Signature *sig;
  /*
   * Fee to pay for close transaction.
   */
  uint64_t close_fee;
};
#define CLOSE_CHANNEL__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&close_channel__descriptor) \
    , NULL, 0 }


/*
 * OK, here's my sig so you can broadcast it too.  We're done.
 */
struct  _CloseChannelComplete
{
  ProtobufCMessage base;
  /*
   * This is my signature for that same tx.
   */
  Signature *sig;
};
#define CLOSE_CHANNEL_COMPLETE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&close_channel_complete__descriptor) \
    , NULL }


/*
 * Received close_channel_complete, you can close now.
 */
struct  _CloseChannelAck
{
  ProtobufCMessage base;
};
#define CLOSE_CHANNEL_ACK__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&close_channel_ack__descriptor) \
     }


/*
 * This means we're going to hang up; it's to help diagnose only! 
 */
struct  _Error
{
  ProtobufCMessage base;
  char *problem;
};
#define ERROR__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&error__descriptor) \
    , NULL }


typedef enum {
  PKT__PKT__NOT_SET = 0,
  PKT__PKT_OPEN = 20,
  PKT__PKT_OPEN_ANCHOR = 21,
  PKT__PKT_OPEN_COMMIT_SIG = 22,
  PKT__PKT_OPEN_COMPLETE = 23,
  PKT__PKT_UPDATE = 1,
  PKT__PKT_UPDATE_ADD_HTLC = 2,
  PKT__PKT_UPDATE_ACCEPT = 3,
  PKT__PKT_UPDATE_SIGNATURE = 4,
  PKT__PKT_UPDATE_COMPLETE = 5,
  PKT__PKT_UPDATE_DECLINE_HTLC = 6,
  PKT__PKT_UPDATE_COMPLETE_HTLC = 7,
  PKT__PKT_UPDATE_TIMEDOUT_HTLC = 8,
  PKT__PKT_UPDATE_ROUTEFAIL_HTLC = 9,
  PKT__PKT_CLOSE = 30,
  PKT__PKT_CLOSE_COMPLETE = 31,
  PKT__PKT_CLOSE_ACK = 32,
  PKT__PKT_ERROR = 40,
} Pkt__PktCase;

/*
 * This is the union which defines all of them
 */
struct  _Pkt
{
  ProtobufCMessage base;
  Pkt__PktCase pkt_case;
  union {
    /*
     * Opening
     */
    OpenChannel *open;
    OpenAnchor *open_anchor;
    OpenCommitSig *open_commit_sig;
    OpenComplete *open_complete;
    /*
     * Updating (most common)
     */
    Update *update;
    UpdateAddHtlc *update_add_htlc;
    UpdateAccept *update_accept;
    UpdateSignature *update_signature;
    UpdateComplete *update_complete;
    UpdateDeclineHtlc *update_decline_htlc;
    UpdateCompleteHtlc *update_complete_htlc;
    UpdateTimedoutHtlc *update_timedout_htlc;
    UpdateRoutefailHtlc *update_routefail_htlc;
    /*
     * Closing
     */
    CloseChannel *close;
    CloseChannelComplete *close_complete;
    CloseChannelAck *close_ack;
    /*
     * Unexpected issue.
     */
    Error *error;
  };
};
#define PKT__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&pkt__descriptor) \
    , PKT__PKT__NOT_SET, {} }


/* Sha256Hash methods */
void   sha256_hash__init
                     (Sha256Hash         *message);
size_t sha256_hash__get_packed_size
                     (const Sha256Hash   *message);
size_t sha256_hash__pack
                     (const Sha256Hash   *message,
                      uint8_t             *out);
size_t sha256_hash__pack_to_buffer
                     (const Sha256Hash   *message,
                      ProtobufCBuffer     *buffer);
Sha256Hash *
       sha256_hash__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   sha256_hash__free_unpacked
                     (Sha256Hash *message,
                      ProtobufCAllocator *allocator);
/* Signature methods */
void   signature__init
                     (Signature         *message);
size_t signature__get_packed_size
                     (const Signature   *message);
size_t signature__pack
                     (const Signature   *message,
                      uint8_t             *out);
size_t signature__pack_to_buffer
                     (const Signature   *message,
                      ProtobufCBuffer     *buffer);
Signature *
       signature__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   signature__free_unpacked
                     (Signature *message,
                      ProtobufCAllocator *allocator);
/* Locktime methods */
void   locktime__init
                     (Locktime         *message);
size_t locktime__get_packed_size
                     (const Locktime   *message);
size_t locktime__pack
                     (const Locktime   *message,
                      uint8_t             *out);
size_t locktime__pack_to_buffer
                     (const Locktime   *message,
                      ProtobufCBuffer     *buffer);
Locktime *
       locktime__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   locktime__free_unpacked
                     (Locktime *message,
                      ProtobufCAllocator *allocator);
/* BitcoinPubkey methods */
void   bitcoin_pubkey__init
                     (BitcoinPubkey         *message);
size_t bitcoin_pubkey__get_packed_size
                     (const BitcoinPubkey   *message);
size_t bitcoin_pubkey__pack
                     (const BitcoinPubkey   *message,
                      uint8_t             *out);
size_t bitcoin_pubkey__pack_to_buffer
                     (const BitcoinPubkey   *message,
                      ProtobufCBuffer     *buffer);
BitcoinPubkey *
       bitcoin_pubkey__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   bitcoin_pubkey__free_unpacked
                     (BitcoinPubkey *message,
                      ProtobufCAllocator *allocator);
/* Funding methods */
void   funding__init
                     (Funding         *message);
size_t funding__get_packed_size
                     (const Funding   *message);
size_t funding__pack
                     (const Funding   *message,
                      uint8_t             *out);
size_t funding__pack_to_buffer
                     (const Funding   *message,
                      ProtobufCBuffer     *buffer);
Funding *
       funding__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   funding__free_unpacked
                     (Funding *message,
                      ProtobufCAllocator *allocator);
/* OpenChannel methods */
void   open_channel__init
                     (OpenChannel         *message);
size_t open_channel__get_packed_size
                     (const OpenChannel   *message);
size_t open_channel__pack
                     (const OpenChannel   *message,
                      uint8_t             *out);
size_t open_channel__pack_to_buffer
                     (const OpenChannel   *message,
                      ProtobufCBuffer     *buffer);
OpenChannel *
       open_channel__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   open_channel__free_unpacked
                     (OpenChannel *message,
                      ProtobufCAllocator *allocator);
/* OpenAnchor methods */
void   open_anchor__init
                     (OpenAnchor         *message);
size_t open_anchor__get_packed_size
                     (const OpenAnchor   *message);
size_t open_anchor__pack
                     (const OpenAnchor   *message,
                      uint8_t             *out);
size_t open_anchor__pack_to_buffer
                     (const OpenAnchor   *message,
                      ProtobufCBuffer     *buffer);
OpenAnchor *
       open_anchor__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   open_anchor__free_unpacked
                     (OpenAnchor *message,
                      ProtobufCAllocator *allocator);
/* OpenCommitSig methods */
void   open_commit_sig__init
                     (OpenCommitSig         *message);
size_t open_commit_sig__get_packed_size
                     (const OpenCommitSig   *message);
size_t open_commit_sig__pack
                     (const OpenCommitSig   *message,
                      uint8_t             *out);
size_t open_commit_sig__pack_to_buffer
                     (const OpenCommitSig   *message,
                      ProtobufCBuffer     *buffer);
OpenCommitSig *
       open_commit_sig__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   open_commit_sig__free_unpacked
                     (OpenCommitSig *message,
                      ProtobufCAllocator *allocator);
/* OpenComplete methods */
void   open_complete__init
                     (OpenComplete         *message);
size_t open_complete__get_packed_size
                     (const OpenComplete   *message);
size_t open_complete__pack
                     (const OpenComplete   *message,
                      uint8_t             *out);
size_t open_complete__pack_to_buffer
                     (const OpenComplete   *message,
                      ProtobufCBuffer     *buffer);
OpenComplete *
       open_complete__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   open_complete__free_unpacked
                     (OpenComplete *message,
                      ProtobufCAllocator *allocator);
/* Update methods */
void   update__init
                     (Update         *message);
size_t update__get_packed_size
                     (const Update   *message);
size_t update__pack
                     (const Update   *message,
                      uint8_t             *out);
size_t update__pack_to_buffer
                     (const Update   *message,
                      ProtobufCBuffer     *buffer);
Update *
       update__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   update__free_unpacked
                     (Update *message,
                      ProtobufCAllocator *allocator);
/* UpdateAddHtlc methods */
void   update_add_htlc__init
                     (UpdateAddHtlc         *message);
size_t update_add_htlc__get_packed_size
                     (const UpdateAddHtlc   *message);
size_t update_add_htlc__pack
                     (const UpdateAddHtlc   *message,
                      uint8_t             *out);
size_t update_add_htlc__pack_to_buffer
                     (const UpdateAddHtlc   *message,
                      ProtobufCBuffer     *buffer);
UpdateAddHtlc *
       update_add_htlc__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   update_add_htlc__free_unpacked
                     (UpdateAddHtlc *message,
                      ProtobufCAllocator *allocator);
/* UpdateDeclineHtlc methods */
void   update_decline_htlc__init
                     (UpdateDeclineHtlc         *message);
size_t update_decline_htlc__get_packed_size
                     (const UpdateDeclineHtlc   *message);
size_t update_decline_htlc__pack
                     (const UpdateDeclineHtlc   *message,
                      uint8_t             *out);
size_t update_decline_htlc__pack_to_buffer
                     (const UpdateDeclineHtlc   *message,
                      ProtobufCBuffer     *buffer);
UpdateDeclineHtlc *
       update_decline_htlc__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   update_decline_htlc__free_unpacked
                     (UpdateDeclineHtlc *message,
                      ProtobufCAllocator *allocator);
/* UpdateCompleteHtlc methods */
void   update_complete_htlc__init
                     (UpdateCompleteHtlc         *message);
size_t update_complete_htlc__get_packed_size
                     (const UpdateCompleteHtlc   *message);
size_t update_complete_htlc__pack
                     (const UpdateCompleteHtlc   *message,
                      uint8_t             *out);
size_t update_complete_htlc__pack_to_buffer
                     (const UpdateCompleteHtlc   *message,
                      ProtobufCBuffer     *buffer);
UpdateCompleteHtlc *
       update_complete_htlc__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   update_complete_htlc__free_unpacked
                     (UpdateCompleteHtlc *message,
                      ProtobufCAllocator *allocator);
/* UpdateTimedoutHtlc methods */
void   update_timedout_htlc__init
                     (UpdateTimedoutHtlc         *message);
size_t update_timedout_htlc__get_packed_size
                     (const UpdateTimedoutHtlc   *message);
size_t update_timedout_htlc__pack
                     (const UpdateTimedoutHtlc   *message,
                      uint8_t             *out);
size_t update_timedout_htlc__pack_to_buffer
                     (const UpdateTimedoutHtlc   *message,
                      ProtobufCBuffer     *buffer);
UpdateTimedoutHtlc *
       update_timedout_htlc__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   update_timedout_htlc__free_unpacked
                     (UpdateTimedoutHtlc *message,
                      ProtobufCAllocator *allocator);
/* UpdateRoutefailHtlc methods */
void   update_routefail_htlc__init
                     (UpdateRoutefailHtlc         *message);
size_t update_routefail_htlc__get_packed_size
                     (const UpdateRoutefailHtlc   *message);
size_t update_routefail_htlc__pack
                     (const UpdateRoutefailHtlc   *message,
                      uint8_t             *out);
size_t update_routefail_htlc__pack_to_buffer
                     (const UpdateRoutefailHtlc   *message,
                      ProtobufCBuffer     *buffer);
UpdateRoutefailHtlc *
       update_routefail_htlc__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   update_routefail_htlc__free_unpacked
                     (UpdateRoutefailHtlc *message,
                      ProtobufCAllocator *allocator);
/* UpdateAccept methods */
void   update_accept__init
                     (UpdateAccept         *message);
size_t update_accept__get_packed_size
                     (const UpdateAccept   *message);
size_t update_accept__pack
                     (const UpdateAccept   *message,
                      uint8_t             *out);
size_t update_accept__pack_to_buffer
                     (const UpdateAccept   *message,
                      ProtobufCBuffer     *buffer);
UpdateAccept *
       update_accept__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   update_accept__free_unpacked
                     (UpdateAccept *message,
                      ProtobufCAllocator *allocator);
/* UpdateSignature methods */
void   update_signature__init
                     (UpdateSignature         *message);
size_t update_signature__get_packed_size
                     (const UpdateSignature   *message);
size_t update_signature__pack
                     (const UpdateSignature   *message,
                      uint8_t             *out);
size_t update_signature__pack_to_buffer
                     (const UpdateSignature   *message,
                      ProtobufCBuffer     *buffer);
UpdateSignature *
       update_signature__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   update_signature__free_unpacked
                     (UpdateSignature *message,
                      ProtobufCAllocator *allocator);
/* UpdateComplete methods */
void   update_complete__init
                     (UpdateComplete         *message);
size_t update_complete__get_packed_size
                     (const UpdateComplete   *message);
size_t update_complete__pack
                     (const UpdateComplete   *message,
                      uint8_t             *out);
size_t update_complete__pack_to_buffer
                     (const UpdateComplete   *message,
                      ProtobufCBuffer     *buffer);
UpdateComplete *
       update_complete__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   update_complete__free_unpacked
                     (UpdateComplete *message,
                      ProtobufCAllocator *allocator);
/* CloseChannel methods */
void   close_channel__init
                     (CloseChannel         *message);
size_t close_channel__get_packed_size
                     (const CloseChannel   *message);
size_t close_channel__pack
                     (const CloseChannel   *message,
                      uint8_t             *out);
size_t close_channel__pack_to_buffer
                     (const CloseChannel   *message,
                      ProtobufCBuffer     *buffer);
CloseChannel *
       close_channel__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   close_channel__free_unpacked
                     (CloseChannel *message,
                      ProtobufCAllocator *allocator);
/* CloseChannelComplete methods */
void   close_channel_complete__init
                     (CloseChannelComplete         *message);
size_t close_channel_complete__get_packed_size
                     (const CloseChannelComplete   *message);
size_t close_channel_complete__pack
                     (const CloseChannelComplete   *message,
                      uint8_t             *out);
size_t close_channel_complete__pack_to_buffer
                     (const CloseChannelComplete   *message,
                      ProtobufCBuffer     *buffer);
CloseChannelComplete *
       close_channel_complete__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   close_channel_complete__free_unpacked
                     (CloseChannelComplete *message,
                      ProtobufCAllocator *allocator);
/* CloseChannelAck methods */
void   close_channel_ack__init
                     (CloseChannelAck         *message);
size_t close_channel_ack__get_packed_size
                     (const CloseChannelAck   *message);
size_t close_channel_ack__pack
                     (const CloseChannelAck   *message,
                      uint8_t             *out);
size_t close_channel_ack__pack_to_buffer
                     (const CloseChannelAck   *message,
                      ProtobufCBuffer     *buffer);
CloseChannelAck *
       close_channel_ack__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   close_channel_ack__free_unpacked
                     (CloseChannelAck *message,
                      ProtobufCAllocator *allocator);
/* Error methods */
void   error__init
                     (Error         *message);
size_t error__get_packed_size
                     (const Error   *message);
size_t error__pack
                     (const Error   *message,
                      uint8_t             *out);
size_t error__pack_to_buffer
                     (const Error   *message,
                      ProtobufCBuffer     *buffer);
Error *
       error__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   error__free_unpacked
                     (Error *message,
                      ProtobufCAllocator *allocator);
/* Pkt methods */
void   pkt__init
                     (Pkt         *message);
size_t pkt__get_packed_size
                     (const Pkt   *message);
size_t pkt__pack
                     (const Pkt   *message,
                      uint8_t             *out);
size_t pkt__pack_to_buffer
                     (const Pkt   *message,
                      ProtobufCBuffer     *buffer);
Pkt *
       pkt__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   pkt__free_unpacked
                     (Pkt *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Sha256Hash_Closure)
                 (const Sha256Hash *message,
                  void *closure_data);
typedef void (*Signature_Closure)
                 (const Signature *message,
                  void *closure_data);
typedef void (*Locktime_Closure)
                 (const Locktime *message,
                  void *closure_data);
typedef void (*BitcoinPubkey_Closure)
                 (const BitcoinPubkey *message,
                  void *closure_data);
typedef void (*Funding_Closure)
                 (const Funding *message,
                  void *closure_data);
typedef void (*OpenChannel_Closure)
                 (const OpenChannel *message,
                  void *closure_data);
typedef void (*OpenAnchor_Closure)
                 (const OpenAnchor *message,
                  void *closure_data);
typedef void (*OpenCommitSig_Closure)
                 (const OpenCommitSig *message,
                  void *closure_data);
typedef void (*OpenComplete_Closure)
                 (const OpenComplete *message,
                  void *closure_data);
typedef void (*Update_Closure)
                 (const Update *message,
                  void *closure_data);
typedef void (*UpdateAddHtlc_Closure)
                 (const UpdateAddHtlc *message,
                  void *closure_data);
typedef void (*UpdateDeclineHtlc_Closure)
                 (const UpdateDeclineHtlc *message,
                  void *closure_data);
typedef void (*UpdateCompleteHtlc_Closure)
                 (const UpdateCompleteHtlc *message,
                  void *closure_data);
typedef void (*UpdateTimedoutHtlc_Closure)
                 (const UpdateTimedoutHtlc *message,
                  void *closure_data);
typedef void (*UpdateRoutefailHtlc_Closure)
                 (const UpdateRoutefailHtlc *message,
                  void *closure_data);
typedef void (*UpdateAccept_Closure)
                 (const UpdateAccept *message,
                  void *closure_data);
typedef void (*UpdateSignature_Closure)
                 (const UpdateSignature *message,
                  void *closure_data);
typedef void (*UpdateComplete_Closure)
                 (const UpdateComplete *message,
                  void *closure_data);
typedef void (*CloseChannel_Closure)
                 (const CloseChannel *message,
                  void *closure_data);
typedef void (*CloseChannelComplete_Closure)
                 (const CloseChannelComplete *message,
                  void *closure_data);
typedef void (*CloseChannelAck_Closure)
                 (const CloseChannelAck *message,
                  void *closure_data);
typedef void (*Error_Closure)
                 (const Error *message,
                  void *closure_data);
typedef void (*Pkt_Closure)
                 (const Pkt *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCMessageDescriptor sha256_hash__descriptor;
extern const ProtobufCMessageDescriptor signature__descriptor;
extern const ProtobufCMessageDescriptor locktime__descriptor;
extern const ProtobufCMessageDescriptor bitcoin_pubkey__descriptor;
extern const ProtobufCMessageDescriptor funding__descriptor;
extern const ProtobufCMessageDescriptor open_channel__descriptor;
extern const ProtobufCEnumDescriptor    open_channel__anchor_offer__descriptor;
extern const ProtobufCMessageDescriptor open_anchor__descriptor;
extern const ProtobufCMessageDescriptor open_commit_sig__descriptor;
extern const ProtobufCMessageDescriptor open_complete__descriptor;
extern const ProtobufCMessageDescriptor update__descriptor;
extern const ProtobufCMessageDescriptor update_add_htlc__descriptor;
extern const ProtobufCMessageDescriptor update_decline_htlc__descriptor;
extern const ProtobufCMessageDescriptor update_complete_htlc__descriptor;
extern const ProtobufCMessageDescriptor update_timedout_htlc__descriptor;
extern const ProtobufCMessageDescriptor update_routefail_htlc__descriptor;
extern const ProtobufCMessageDescriptor update_accept__descriptor;
extern const ProtobufCMessageDescriptor update_signature__descriptor;
extern const ProtobufCMessageDescriptor update_complete__descriptor;
extern const ProtobufCMessageDescriptor close_channel__descriptor;
extern const ProtobufCMessageDescriptor close_channel_complete__descriptor;
extern const ProtobufCMessageDescriptor close_channel_ack__descriptor;
extern const ProtobufCMessageDescriptor error__descriptor;
extern const ProtobufCMessageDescriptor pkt__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_lightning_2eproto__INCLUDED */
