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

#endif /* MERKLE_H_ */
