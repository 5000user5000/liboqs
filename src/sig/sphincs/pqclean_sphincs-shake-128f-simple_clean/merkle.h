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
 *
 * For SPHINCS+-128f:
 *   SPX_N = 16, SPX_D = 22, SPX_TREE_HEIGHT = 3, SPX_TREE_LEAVES = 8
 *
 * Very small trees enable deep caching:
 *   - 1 layer: 384 B, ~4.5% speedup
 *   - 2 layers: 3.4 KB, ~9% speedup
 *   - 6 layers: 8.6 MB, ~27% speedup
 *============================================================================*/

/* Number of leaves in each XMSS tree */
#define SPX_TREE_LEAVES (1 << SPX_TREE_HEIGHT)  /* 2^3 = 8 for 128f */

/* Maximum root-down cacheable layers under the 1 GiB study cap. */
#define SPX_CACHE_MAX_LAYERS 7

/*
 * Single layer cache: stores auth paths for one tree
 * Size for 128f: 8 × 3 × 16 = 384 bytes per tree
 */
typedef struct {
    unsigned char auth_paths[SPX_TREE_LEAVES][SPX_TREE_HEIGHT * SPX_N];
} spx_layer_tree_cache;

typedef struct {
    uint64_t tree_count;
    spx_layer_tree_cache *trees;
} spx_cache_layer_set;

/*
 * Dynamic root-down cache structure for SPHINCS+-128f.
 *
 * cached layer set 0: layer 21 (top), 1 tree
 * cached layer set 1: layer 20, 8 trees
 * ...
 * cached layer set 6: layer 15, 8^6 trees
 */
typedef struct {
    int num_layers;
    int initialized;
    spx_cache_layer_set layer_sets[SPX_CACHE_MAX_LAYERS];
} spx_multilayer_cache;

typedef enum {
    SPX_ENTRY_CACHE_FIFO = 0,
    SPX_ENTRY_CACHE_LRU = 1,
    SPX_ENTRY_CACHE_STRUCTURE_AWARE = 2
} spx_entry_cache_policy;

typedef struct {
    int valid;
    int layer_from_top;
    uint64_t tree_index;
    uint64_t insertion_sequence;
    uint64_t last_access_sequence;
    spx_layer_tree_cache tree;
} spx_entry_cache_item;

typedef struct {
    int initialized;
    int key_bound;
    uint8_t key_id[2 * SPX_N];
    size_t capacity;
    size_t size;
    spx_entry_cache_policy policy;
    uint64_t sequence;
    uint64_t accesses;
    uint64_t hits;
    uint64_t misses;
    uint64_t insertions;
    uint64_t evictions;
    uint64_t bypasses;
    spx_entry_cache_item *entries;
} spx_entry_cache;

/* Backward compatibility */
typedef struct {
    int initialized;
    unsigned char leaves[SPX_TREE_LEAVES][SPX_N];
    unsigned char auth_paths[SPX_TREE_LEAVES][SPX_TREE_HEIGHT * SPX_N];
} spx_top_cache;

/* Initialize multi-layer cache (1 to SPX_CACHE_MAX_LAYERS root-down layers) */
#define merkle_init_multilayer_cache SPX_NAMESPACE(merkle_init_multilayer_cache)
void merkle_init_multilayer_cache(spx_multilayer_cache *cache,
                                   const spx_ctx *ctx,
                                   int num_layers);

#define merkle_free_multilayer_cache SPX_NAMESPACE(merkle_free_multilayer_cache)
void merkle_free_multilayer_cache(spx_multilayer_cache *cache);

#define merkle_init_entry_cache SPX_NAMESPACE(merkle_init_entry_cache)
int merkle_init_entry_cache(spx_entry_cache *cache, size_t capacity,
                            spx_entry_cache_policy policy);

#define merkle_free_entry_cache SPX_NAMESPACE(merkle_free_entry_cache)
void merkle_free_entry_cache(spx_entry_cache *cache);

/* Initialize the top layer cache (backward compatible) */
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

#define merkle_sign_entry_cached SPX_NAMESPACE(merkle_sign_entry_cached)
void merkle_sign_entry_cached(uint8_t *sig, unsigned char *root,
                              const spx_ctx *ctx,
                              uint32_t wots_addr[8], uint32_t tree_addr[8],
                              uint32_t idx_leaf, uint64_t tree_index,
                              int layer, spx_entry_cache *cache);

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
 * For 128f: 22 layers, each ~7ms → max blocking reduced from 150ms to 7ms
 *============================================================================*/

typedef enum {
    SPX_SIGN_STATE_INIT = 0,       /* Initial state, ready to start */
    SPX_SIGN_STATE_FORS_DONE,      /* FORS completed, ready for Hypertree */
    SPX_SIGN_STATE_LAYER_DONE,     /* A layer completed, can preempt here */
    SPX_SIGN_STATE_COMPLETE        /* Signing completed */
} spx_sign_state;

/*
 * Context for preemptive signing.
 * Size: ~250 bytes (extremely low overhead)
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
