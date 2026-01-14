#ifndef MERKLE_H_
#define MERKLE_H_

#include <stdint.h>

#include "context.h"
#include "params.h"

/* Generate a Merkle signature (WOTS signature followed by the Merkle */
/* authentication path) */
#define merkle_sign SPX_NAMESPACE(merkle_sign)
void merkle_sign(uint8_t *sig, unsigned char *root,
                 const spx_ctx *ctx,
                 uint32_t wots_addr[8], uint32_t tree_addr[8],
                 uint32_t idx_leaf);

/* Compute the root node of the top-most subtree. */
#define merkle_gen_root SPX_NAMESPACE(merkle_gen_root)
void merkle_gen_root(unsigned char *root, const spx_ctx *ctx);

/*============================================================================
 * Multi-Layer Cache Support (Method 2: Static Top-Layer Caching)
 *============================================================================*/

/* Number of leaves in each XMSS tree */
#define SPX_TREE_LEAVES (1 << SPX_TREE_HEIGHT)  /* 2^4 = 16 for 256f */

/* Maximum cacheable layers (configurable) */
#define SPX_CACHE_MAX_LAYERS 2

/*
 * Single layer cache: stores auth paths for one tree
 * Size: 16 auth_paths × 4 nodes × 32 bytes = 2,048 bytes
 */
typedef struct {
    unsigned char auth_paths[SPX_TREE_LEAVES][SPX_TREE_HEIGHT * SPX_N];
} spx_layer_tree_cache;

/*
 * Multi-layer cache structure
 *
 * For SPHINCS+-256f with 2 layers cached:
 * - Layer 16 (top): 1 tree → 2 KB
 * - Layer 15: 16 trees → 32 KB
 * - Total: ~34 KB
 *
 * Expected speedup: 2 layers / 17 total ≈ 11.8%
 */
typedef struct {
    /* Number of layers actually cached (1 or 2) */
    int num_layers;

    /* Flag indicating if cache is initialized */
    int initialized;

    /* Layer 16 (top layer, index SPX_D-1): 1 tree */
    spx_layer_tree_cache top_layer;

    /* Layer 15 (second layer, index SPX_D-2): 16 trees
     * Tree index is determined by idx_leaf from layer 16 */
    spx_layer_tree_cache second_layer[SPX_TREE_LEAVES];

} spx_multilayer_cache;

/* Backward compatibility: single layer cache is just the top part */
typedef struct {
    int initialized;
    unsigned char leaves[SPX_TREE_LEAVES][SPX_N];
    unsigned char auth_paths[SPX_TREE_LEAVES][SPX_TREE_HEIGHT * SPX_N];
} spx_top_cache;

/* Initialize multi-layer cache (1 or 2 layers) */
#define merkle_init_multilayer_cache SPX_NAMESPACE(merkle_init_multilayer_cache)
void merkle_init_multilayer_cache(spx_multilayer_cache *cache,
                                   const spx_ctx *ctx,
                                   int num_layers);

/* Initialize the top layer cache (backward compatible, 1 layer only) */
#define merkle_init_top_cache SPX_NAMESPACE(merkle_init_top_cache)
void merkle_init_top_cache(spx_top_cache *cache, const spx_ctx *ctx);

/* Generate a Merkle signature using multi-layer cached data */
#define merkle_sign_multilayer_cached SPX_NAMESPACE(merkle_sign_multilayer_cached)
void merkle_sign_multilayer_cached(uint8_t *sig, unsigned char *root,
                                    const spx_ctx *ctx,
                                    uint32_t wots_addr[8], uint32_t tree_addr[8],
                                    uint32_t idx_leaf, uint64_t tree_index,
                                    int layer,
                                    const spx_multilayer_cache *cache);

/* Generate a Merkle signature using cached top layer data (backward compatible) */
#define merkle_sign_cached SPX_NAMESPACE(merkle_sign_cached)
void merkle_sign_cached(uint8_t *sig, unsigned char *root,
                        const spx_ctx *ctx,
                        uint32_t wots_addr[8], uint32_t tree_addr[8],
                        uint32_t idx_leaf,
                        const spx_top_cache *cache);

/*============================================================================
 * Method 1: Preemptive Signing API (Layer-Level Preemption)
 *
 * Enables preemption between Hypertree layers to reduce Head-of-Line blocking.
 * For 256f: 17 layers, each ~29ms → max blocking reduced from 500ms to 29ms
 *============================================================================*/

typedef enum {
    SPX_SIGN_STATE_INIT = 0,       /* Initial state, ready to start */
    SPX_SIGN_STATE_FORS_DONE,      /* FORS completed, ready for Hypertree */
    SPX_SIGN_STATE_LAYER_DONE,     /* A layer completed, can preempt here */
    SPX_SIGN_STATE_COMPLETE        /* Signing completed */
} spx_sign_state;

/*
 * Context for preemptive signing.
 * Size: ~300 bytes (extremely low overhead)
 *
 * This context preserves all state needed to pause and resume signing
 * between Hypertree layers.
 */
typedef struct {
    /* State tracking */
    spx_sign_state state;
    int current_layer;             /* Current layer (0 to SPX_D-1) */

    /* Inter-layer values */
    uint64_t tree;                 /* Current tree index */
    uint32_t idx_leaf;             /* Leaf node index */
    uint8_t *sig_ptr;              /* Current position in signature buffer */

    /* Intermediate computation results */
    uint8_t root[SPX_N];           /* Intermediate root value */
    uint8_t mhash[SPX_FORS_MSG_BYTES]; /* Message hash (unchanged after FORS) */

    /* Crypto Context */
    spx_ctx ctx;                   /* pub_seed, sk_seed */
    uint32_t wots_addr[8];         /* WOTS address */
    uint32_t tree_addr[8];         /* Tree address */

    /* Metadata */
    uint8_t *sig_start;            /* Signature buffer start position */
    size_t siglen;                 /* Final signature length */
} spx_sign_ctx;

/**
 * Initialize a preemptive signing context.
 *
 * This performs:
 * - Context initialization
 * - Random value generation
 * - Message hashing
 * - FORS signing (~20% of total time)
 *
 * After this call, the context is ready for layer-by-layer Hypertree signing.
 *
 * @param sctx     Signing context (must be pre-allocated)
 * @param sig      Signature output buffer
 * @param m        Message to sign
 * @param mlen     Message length
 * @param sk       Secret key
 * @return         0 on success, -1 on failure
 */
#define crypto_sign_preempt_init SPX_NAMESPACE(crypto_sign_preempt_init)
int crypto_sign_preempt_init(spx_sign_ctx *sctx,
                              uint8_t *sig,
                              const uint8_t *m, size_t mlen,
                              const uint8_t *sk);

/**
 * Execute one signing step (one Hypertree layer).
 *
 * Each call processes exactly one layer of the Hypertree.
 * Between calls, the context can be saved and higher-priority
 * operations can be executed.
 *
 * @param sctx     Signing context
 * @return         SPX_SIGN_STATE_LAYER_DONE: can continue or preempt
 *                 SPX_SIGN_STATE_COMPLETE: signing finished
 *                 -1: error
 */
#define crypto_sign_preempt_step SPX_NAMESPACE(crypto_sign_preempt_step)
int crypto_sign_preempt_step(spx_sign_ctx *sctx);

/**
 * Check if signing is complete.
 *
 * @param sctx     Signing context
 * @return         1 if complete, 0 otherwise
 */
#define crypto_sign_preempt_is_complete SPX_NAMESPACE(crypto_sign_preempt_is_complete)
int crypto_sign_preempt_is_complete(const spx_sign_ctx *sctx);

/**
 * Get signature length (call after completion).
 *
 * @param sctx     Signing context
 * @return         Signature length in bytes
 */
#define crypto_sign_preempt_siglen SPX_NAMESPACE(crypto_sign_preempt_siglen)
size_t crypto_sign_preempt_siglen(const spx_sign_ctx *sctx);

/**
 * Get the number of remaining layers.
 *
 * @param sctx     Signing context
 * @return         Number of layers remaining (0 when complete)
 */
#define crypto_sign_preempt_remaining_layers SPX_NAMESPACE(crypto_sign_preempt_remaining_layers)
int crypto_sign_preempt_remaining_layers(const spx_sign_ctx *sctx);

/**
 * Cleanup signing context.
 * Securely clears sensitive data from the context.
 *
 * @param sctx     Signing context
 */
#define crypto_sign_preempt_cleanup SPX_NAMESPACE(crypto_sign_preempt_cleanup)
void crypto_sign_preempt_cleanup(spx_sign_ctx *sctx);

#endif /* MERKLE_H_ */
