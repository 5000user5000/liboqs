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

/* Maximum cacheable layers */
#define SPX_CACHE_MAX_LAYERS 2

/*
 * Single layer cache: stores auth paths for one tree
 * Size for 128f: 8 × 3 × 16 = 384 bytes per tree
 */
typedef struct {
    unsigned char auth_paths[SPX_TREE_LEAVES][SPX_TREE_HEIGHT * SPX_N];
} spx_layer_tree_cache;

/*
 * Multi-layer cache structure for SPHINCS+-128f
 *
 * For 2 layers cached:
 *   - Layer 21 (top): 1 tree → 384 B
 *   - Layer 20: 8 trees → 3 KB
 *   - Total: ~3.4 KB for 2 layers
 *
 * Expected speedup: 2 layers / 22 total ≈ 9.1%
 */
typedef struct {
    int num_layers;
    int initialized;

    /* Layer 21 (top layer, index SPX_D-1): 1 tree */
    spx_layer_tree_cache top_layer;

    /* Layer 20 (second layer, index SPX_D-2): 8 trees */
    spx_layer_tree_cache second_layer[SPX_TREE_LEAVES];

} spx_multilayer_cache;

/* Backward compatibility */
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

/* Generate a Merkle signature using cached top layer data (backward compatible) */
#define merkle_sign_cached SPX_NAMESPACE(merkle_sign_cached)
void merkle_sign_cached(uint8_t *sig, unsigned char *root,
                        const spx_ctx *ctx,
                        uint32_t wots_addr[8], uint32_t tree_addr[8],
                        uint32_t idx_leaf,
                        const spx_top_cache *cache);

#endif /* MERKLE_H_ */
