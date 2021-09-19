/* This file was generated by generate-wire.py */
/* Do not modify this file! Modify the _csv file it was generated from. */
/* Original template can be found at tools/gen/header_template */

#ifndef LIGHTNING_WIRE_COMMON_WIREGEN_H
#define LIGHTNING_WIRE_COMMON_WIREGEN_H
#include <ccan/tal/tal.h>
#include <wire/tlvstream.h>
#include <wire/wire.h>

enum common_wire {
        /*  A custom message that we got from a peer and don't know how to handle */
        /*  forward it to the master for further handling. */
        WIRE_CUSTOMMSG_IN = 1030,
        /*  A custom message that the master tells us to send to the peer. */
        WIRE_CUSTOMMSG_OUT = 1031,
};

const char *common_wire_name(int e);

/**
 * Determine whether a given message type is defined as a message.
 *
 * Returns true if the message type is part of the message definitions we have
 * generated parsers for, false if it is a custom message that cannot be
 * handled internally.
 */
bool common_wire_is_defined(u16 type);


/* WIRE: CUSTOMMSG_IN */
/*  A custom message that we got from a peer and don't know how to handle */
/*  forward it to the master for further handling. */
u8 *towire_custommsg_in(const tal_t *ctx, const u8 *msg);
bool fromwire_custommsg_in(const tal_t *ctx, const void *p, u8 **msg);

/* WIRE: CUSTOMMSG_OUT */
/*  A custom message that the master tells us to send to the peer. */
u8 *towire_custommsg_out(const tal_t *ctx, const u8 *msg);
bool fromwire_custommsg_out(const tal_t *ctx, const void *p, u8 **msg);


#endif /* LIGHTNING_WIRE_COMMON_WIREGEN_H */
// SHA256STAMP:a0d8998b1f9bd46677f237471545a49b8009e41b8b3afedf0007adeabf98b440
