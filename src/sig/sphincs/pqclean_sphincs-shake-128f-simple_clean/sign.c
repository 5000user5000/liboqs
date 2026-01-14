#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "address.h"
#include "context.h"
#include "fors.h"
#include "hash.h"
#include "merkle.h"
#include "nistapi.h"
#include "params.h"
#include "randombytes.h"
#include "thash.h"
#include "utils.h"
#include "wots.h"

/*
 * Returns the length of a secret key, in bytes
 */
size_t crypto_sign_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

/*
 * Returns the length of a public key, in bytes
 */
size_t crypto_sign_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

/*
 * Returns the length of a signature, in bytes
 */
size_t crypto_sign_bytes(void) {
    return CRYPTO_BYTES;
}

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
size_t crypto_sign_seedbytes(void) {
    return CRYPTO_SEEDBYTES;
}

/*
 * Generates an SPX key pair given a seed of length
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_seed_keypair(uint8_t *pk, uint8_t *sk,
                             const uint8_t *seed) {
    spx_ctx ctx;

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    memcpy(sk, seed, CRYPTO_SEEDBYTES);

    memcpy(pk, sk + 2 * SPX_N, SPX_N);

    memcpy(ctx.pub_seed, pk, SPX_N);
    memcpy(ctx.sk_seed, sk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    /* Compute root node of the top-most subtree. */
    merkle_gen_root(sk + 3 * SPX_N, &ctx);

    // cleanup
    free_hash_function(&ctx);

    memcpy(pk + SPX_N, sk + 3 * SPX_N, SPX_N);

    return 0;
}

/*
 * Generates an SPX key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [PUB_SEED || root]
 */
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    uint8_t seed[CRYPTO_SEEDBYTES];
    randombytes(seed, CRYPTO_SEEDBYTES);
    crypto_sign_seed_keypair(pk, sk, seed);

    return 0;
}

/**
 * Returns an array containing a detached signature.
 */
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk) {
    spx_ctx ctx;

    const uint8_t *sk_prf = sk + SPX_N;
    const uint8_t *pk = sk + 2 * SPX_N;

    uint8_t optrand[SPX_N];
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t root[SPX_N];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    randombytes(optrand, SPX_N);
    /* Compute the digest randomization value. */
    gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    free_hash_function(&ctx);

    *siglen = SPX_BYTES;

    return 0;
}

/**
 * Verifies a detached signature and message under a given public key.
 */
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk) {
    spx_ctx ctx;
    const uint8_t *pub_root = pk + SPX_N;
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t wots_pk[SPX_WOTS_BYTES];
    uint8_t root[SPX_N];
    uint8_t leaf[SPX_N];
    unsigned int i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};
    uint32_t wots_pk_addr[8] = {0};

    if (siglen != SPX_BYTES) {
        return -1;
    }

    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    /* Derive the message digest and leaf index from R || PK || M. */
    /* The additional SPX_N is a result of the hash domain separator. */
    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    /* Layer correctly defaults to 0, so no need to set_layer_addr */
    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_pk_from_sig(root, sig, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    /* For each subtree.. */
    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        copy_keypair_addr(wots_pk_addr, wots_addr);

        /* The WOTS public key is only correct if the signature was correct. */
        /* Initially, root is the FORS pk, but on subsequent iterations it is
           the root of the subtree below the currently processed subtree. */
        wots_pk_from_sig(wots_pk, sig, root, &ctx, wots_addr);
        sig += SPX_WOTS_BYTES;

        /* Compute the leaf node using the WOTS public key. */
        thash(leaf, wots_pk, SPX_WOTS_LEN, &ctx, wots_pk_addr);

        /* Compute the root node of this subtree. */
        compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT,
                     &ctx, tree_addr);
        sig += SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    // cleanup
    free_hash_function(&ctx);

    /* Check if the root node equals the root node in the public key. */
    if (memcmp(root, pub_root, SPX_N) != 0) {
        return -1;
    }

    return 0;
}

/**
 * Returns an array containing the signature followed by the message.
 */
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk) {
    size_t siglen;

    crypto_sign_signature(sm, &siglen, m, mlen, sk);

    memmove(sm + SPX_BYTES, m, mlen);
    *smlen = siglen + mlen;

    return 0;
}

/**
 * Verifies a given signature-message pair under a given public key.
 */
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk) {
    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly SPX_BYTES. */
    if (smlen < SPX_BYTES) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    *mlen = smlen - SPX_BYTES;

    if (crypto_sign_verify(sm, SPX_BYTES, sm + SPX_BYTES, *mlen, pk)) {
        memset(m, 0, smlen);
        *mlen = 0;
        return -1;
    }

    /* If verification was successful, move the message to the right place. */
    memmove(m, sm + SPX_BYTES, *mlen);

    return 0;
}

/*============================================================================
 * Multi-Layer Cache Support (Method 2: Static Top-Layer Caching)
 *============================================================================*/

int crypto_sign_init_multilayer_cache(spx_multilayer_cache *cache,
                                       const uint8_t *sk,
                                       int num_layers) {
    spx_ctx ctx;
    const uint8_t *pk = sk + 2 * SPX_N;

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    initialize_hash_function(&ctx);

    merkle_init_multilayer_cache(cache, &ctx, num_layers);

    free_hash_function(&ctx);

    return 0;
}

int crypto_sign_signature_multilayer_cached(uint8_t *sig, size_t *siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *sk,
                                             const spx_multilayer_cache *cache) {
    spx_ctx ctx;

    const uint8_t *sk_prf = sk + SPX_N;
    const uint8_t *pk = sk + 2 * SPX_N;

    uint8_t optrand[SPX_N];
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t root[SPX_N];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    uint64_t tree_indices[SPX_D];

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    randombytes(optrand, SPX_N);
    gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);

    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_sign(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    /* Pre-compute tree indices */
    {
        uint64_t t = tree;
        for (i = 0; i < SPX_D; i++) {
            tree_indices[i] = t;
            t = t >> SPX_TREE_HEIGHT;
        }
    }

    tree = tree_indices[0];

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        if (cache && cache->initialized &&
            (i == SPX_D - 1 || (i == SPX_D - 2 && cache->num_layers >= 2))) {
            uint64_t cache_tree_idx = 0;
            if (i == SPX_D - 2) {
                cache_tree_idx = tree_indices[SPX_D - 1] & ((1 << SPX_TREE_HEIGHT) - 1);
            }
            merkle_sign_multilayer_cached(sig, root, &ctx, wots_addr, tree_addr,
                                           idx_leaf, cache_tree_idx, i, cache);
        } else {
            merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        }
        sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    free_hash_function(&ctx);

    *siglen = SPX_BYTES;

    return 0;
}

int crypto_sign_init_cache(spx_top_cache *cache, const uint8_t *sk) {
    spx_ctx ctx;
    const uint8_t *pk = sk + 2 * SPX_N;

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    initialize_hash_function(&ctx);

    merkle_init_top_cache(cache, &ctx);

    free_hash_function(&ctx);

    return 0;
}

int crypto_sign_signature_cached(uint8_t *sig, size_t *siglen,
                                 const uint8_t *m, size_t mlen,
                                 const uint8_t *sk,
                                 const spx_top_cache *cache) {
    spx_ctx ctx;

    const uint8_t *sk_prf = sk + SPX_N;
    const uint8_t *pk = sk + 2 * SPX_N;

    uint8_t optrand[SPX_N];
    uint8_t mhash[SPX_FORS_MSG_BYTES];
    uint8_t root[SPX_N];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, sk, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    randombytes(optrand, SPX_N);
    gen_message_random(sig, sk_prf, optrand, m, mlen, &ctx);

    hash_message(mhash, &tree, &idx_leaf, sig, pk, m, mlen, &ctx);
    sig += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    fors_sign(sig, root, mhash, &ctx, wots_addr);
    sig += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        if (i == SPX_D - 1 && cache && cache->initialized) {
            merkle_sign_cached(sig, root, &ctx, wots_addr, tree_addr,
                              idx_leaf, cache);
        } else {
            merkle_sign(sig, root, &ctx, wots_addr, tree_addr, idx_leaf);
        }
        sig += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
        tree = tree >> SPX_TREE_HEIGHT;
    }

    free_hash_function(&ctx);

    *siglen = SPX_BYTES;

    return 0;
}

/*============================================================================
 * Method 1: Preemptive Signing API (Layer-Level Preemption)
 *============================================================================*/

int crypto_sign_preempt_init(spx_sign_ctx *sctx,
                              uint8_t *sig,
                              const uint8_t *m, size_t mlen,
                              const uint8_t *sk) {
    const uint8_t *sk_prf = sk + SPX_N;
    const uint8_t *pk = sk + 2 * SPX_N;
    uint8_t optrand[SPX_N];

    /* Initialize context */
    sctx->state = SPX_SIGN_STATE_INIT;
    sctx->current_layer = 0;
    sctx->sig_start = sig;
    sctx->sig_ptr = sig;
    sctx->siglen = 0;

    /* Initialize crypto context */
    memcpy(sctx->ctx.sk_seed, sk, SPX_N);
    memcpy(sctx->ctx.pub_seed, pk, SPX_N);
    initialize_hash_function(&sctx->ctx);

    /* Initialize addresses */
    memset(sctx->wots_addr, 0, sizeof(sctx->wots_addr));
    memset(sctx->tree_addr, 0, sizeof(sctx->tree_addr));
    set_type(sctx->wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(sctx->tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Generate randomization value */
    randombytes(optrand, SPX_N);
    gen_message_random(sctx->sig_ptr, sk_prf, optrand, m, mlen, &sctx->ctx);

    /* Derive message digest and leaf index */
    hash_message(sctx->mhash, &sctx->tree, &sctx->idx_leaf,
                 sctx->sig_ptr, pk, m, mlen, &sctx->ctx);
    sctx->sig_ptr += SPX_N;

    /* Set initial addresses for FORS */
    set_tree_addr(sctx->wots_addr, sctx->tree);
    set_keypair_addr(sctx->wots_addr, sctx->idx_leaf);

    /* Sign the message hash using FORS */
    fors_sign(sctx->sig_ptr, sctx->root, sctx->mhash, &sctx->ctx, sctx->wots_addr);
    sctx->sig_ptr += SPX_FORS_BYTES;

    /* FORS done, ready for Hypertree */
    sctx->state = SPX_SIGN_STATE_FORS_DONE;
    sctx->current_layer = 0;

    return 0;
}

int crypto_sign_preempt_step(spx_sign_ctx *sctx) {
    if (sctx->state == SPX_SIGN_STATE_COMPLETE) {
        return SPX_SIGN_STATE_COMPLETE;
    }

    if (sctx->state == SPX_SIGN_STATE_INIT) {
        /* Should have called init first */
        return -1;
    }

    if (sctx->current_layer >= SPX_D) {
        /* Already complete */
        sctx->state = SPX_SIGN_STATE_COMPLETE;
        sctx->siglen = SPX_BYTES;
        free_hash_function(&sctx->ctx);
        return SPX_SIGN_STATE_COMPLETE;
    }

    /* Execute one Hypertree layer */
    int i = sctx->current_layer;

    set_layer_addr(sctx->tree_addr, i);
    set_tree_addr(sctx->tree_addr, sctx->tree);

    copy_subtree_addr(sctx->wots_addr, sctx->tree_addr);
    set_keypair_addr(sctx->wots_addr, sctx->idx_leaf);

    merkle_sign(sctx->sig_ptr, sctx->root, &sctx->ctx,
                sctx->wots_addr, sctx->tree_addr, sctx->idx_leaf);
    sctx->sig_ptr += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

    /* Update indices for next layer */
    sctx->idx_leaf = (sctx->tree & ((1 << SPX_TREE_HEIGHT) - 1));
    sctx->tree = sctx->tree >> SPX_TREE_HEIGHT;

    sctx->current_layer++;

    if (sctx->current_layer >= SPX_D) {
        /* Signing complete */
        sctx->state = SPX_SIGN_STATE_COMPLETE;
        sctx->siglen = SPX_BYTES;
        free_hash_function(&sctx->ctx);
        return SPX_SIGN_STATE_COMPLETE;
    }

    sctx->state = SPX_SIGN_STATE_LAYER_DONE;
    return SPX_SIGN_STATE_LAYER_DONE;
}

int crypto_sign_preempt_is_complete(const spx_sign_ctx *sctx) {
    return sctx->state == SPX_SIGN_STATE_COMPLETE;
}

size_t crypto_sign_preempt_siglen(const spx_sign_ctx *sctx) {
    return sctx->siglen;
}

int crypto_sign_preempt_remaining_layers(const spx_sign_ctx *sctx) {
    if (sctx->state == SPX_SIGN_STATE_COMPLETE) {
        return 0;
    }
    return SPX_D - sctx->current_layer;
}

void crypto_sign_preempt_cleanup(spx_sign_ctx *sctx) {
    /* Securely clear sensitive data */
    memset(sctx->ctx.sk_seed, 0, SPX_N);
    memset(sctx->root, 0, SPX_N);
    memset(sctx->mhash, 0, SPX_FORS_MSG_BYTES);
    sctx->state = SPX_SIGN_STATE_INIT;
}
