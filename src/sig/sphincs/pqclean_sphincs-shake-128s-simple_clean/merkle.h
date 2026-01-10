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
 * For SPHINCS+-128s:
 *   SPX_N = 16, SPX_D = 7, SPX_TREE_HEIGHT = 9, SPX_TREE_LEAVES = 512
 *
 * Auth-path approach (simpler, 1 layer only):
 *   - Per tree: 512 auth paths × 9 × 16 = 73,728 bytes ≈ 72 KB
 *   - 1 layer: ~72 KB, expected speedup: 14.3%
 *============================================================================*/

/* Number of leaves in each XMSS tree */
#define SPX_TREE_LEAVES (1 << SPX_TREE_HEIGHT)  /* 2^9 = 512 for 128s */

/* Maximum cacheable layers (limited to 1 for 128s due to size) */
#define SPX_CACHE_MAX_LAYERS 1

/*
 * Single layer cache using auth paths
 * Size for 128s: 512 × 9 × 16 = 73,728 bytes ≈ 72 KB
 */
typedef struct {
    unsigned char auth_paths[SPX_TREE_LEAVES][SPX_TREE_HEIGHT * SPX_N];
} spx_layer_tree_cache;

/*
 * Multi-layer cache structure for SPHINCS+-128s
 * Note: Only 1 layer supported due to memory constraints
 */
typedef struct {
    int num_layers;
    int initialized;
    spx_layer_tree_cache top_layer;
} spx_multilayer_cache;

/* Backward compatibility */
typedef struct {
    int initialized;
    unsigned char leaves[SPX_TREE_LEAVES][SPX_N];
    unsigned char auth_paths[SPX_TREE_LEAVES][SPX_TREE_HEIGHT * SPX_N];
} spx_top_cache;

/* Initialize multi-layer cache */
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
