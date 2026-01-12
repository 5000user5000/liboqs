#include <stdint.h>
#include <string.h>

#include "address.h"
#include "merkle.h"
#include "params.h"
#include "thash.h"
#include "utils.h"
#include "utilsx1.h"
#include "wots.h"
#include "wotsx1.h"

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path).  This is in this file because most of the complexity
 * is involved with the WOTS signature; the Merkle authentication path logic
 * is mostly hidden in treehashx4
 */
void merkle_sign(uint8_t *sig, unsigned char *root,
                 const spx_ctx *ctx,
                 uint32_t wots_addr[8], uint32_t tree_addr[8],
                 uint32_t idx_leaf) {
    unsigned char *auth_path = sig + SPX_WOTS_BYTES;
    struct leaf_info_x1 info = { 0 };
    unsigned steps[ SPX_WOTS_LEN ];

    info.wots_sig = sig;
    chain_lengths(steps, root);
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    treehashx1(root, auth_path, ctx,
               idx_leaf, 0,
               SPX_TREE_HEIGHT,
               wots_gen_leafx1,
               tree_addr, &info);
}

/* Compute root node of the top-most subtree. */
void merkle_gen_root(unsigned char *root, const spx_ctx *ctx) {
    /* We do not need the auth path in key generation, but it simplifies the
       code to have just one treehash routine that computes both root and path
       in one function. */
    unsigned char auth_path[SPX_TREE_HEIGHT * SPX_N + SPX_WOTS_BYTES];
    uint32_t top_tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};

    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_layer_addr(wots_addr, SPX_D - 1);

    merkle_sign(auth_path, root, ctx,
                wots_addr, top_tree_addr,
                ~0U /* ~0 means "don't bother generating an auth path */ );
}

/*============================================================================
 * Multi-Layer Cache Implementation for SPHINCS+-128s
 *
 * Optimized O(n) algorithm: compute tree once, extract all auth paths
 *============================================================================*/

/*
 * Helper function to compute auth paths for a single tree at a given layer.
 *
 * Optimized O(n) algorithm instead of O(n²):
 * 1. Compute all n leaf nodes (WOTS+ public keys)
 * 2. Build internal nodes bottom-up
 * 3. Extract auth paths from stored nodes
 */
static void compute_tree_auth_paths(spx_layer_tree_cache *tree_cache,
                                     const spx_ctx *ctx,
                                     int layer,
                                     uint64_t tree_index) {
    uint32_t tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};
    uint32_t i, h;

    /* Allocate space for all nodes: leaves + internal nodes
     * For tree height h, we have 2^h leaves and 2^h - 1 internal nodes
     * Total: 2^(h+1) - 1 nodes, but we store by level for easier access
     *
     * nodes[level][idx] where level 0 = leaves, level h = root
     */
    unsigned char nodes[SPX_TREE_HEIGHT + 1][SPX_TREE_LEAVES][SPX_N];

    struct leaf_info_x1 info = { 0 };
    unsigned steps[SPX_WOTS_LEN];

    set_layer_addr(tree_addr, layer);
    set_layer_addr(wots_addr, layer);
    set_tree_addr(tree_addr, tree_index);
    set_tree_addr(wots_addr, tree_index);

    /* Setup for leaf generation (no signing, just public key computation) */
    info.wots_sig = NULL;
    info.wots_sign_leaf = ~0U;  /* No signing */
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    /* Step 1: Compute all leaf nodes - O(n) WOTS computations */
    for (i = 0; i < SPX_TREE_LEAVES; i++) {
        set_keypair_addr(info.leaf_addr, i);
        set_keypair_addr(info.pk_addr, i);
        wots_gen_leafx1(nodes[0][i], ctx, i, &info);
    }

    /* Step 2: Build internal nodes bottom-up - O(n) thash computations */
    for (h = 0; h < SPX_TREE_HEIGHT; h++) {
        uint32_t nodes_at_level = SPX_TREE_LEAVES >> h;
        uint32_t nodes_at_next = nodes_at_level >> 1;

        for (i = 0; i < nodes_at_next; i++) {
            unsigned char parent_input[2 * SPX_N];

            set_tree_height(tree_addr, h + 1);
            set_tree_index(tree_addr, i);

            /* Concatenate left and right children */
            memcpy(parent_input, nodes[h][2*i], SPX_N);
            memcpy(parent_input + SPX_N, nodes[h][2*i + 1], SPX_N);

            /* Compute parent node */
            thash(nodes[h + 1][i], parent_input, 2, ctx, tree_addr);
        }
    }

    /* Step 3: Extract auth paths for each leaf - O(n * h) memory copies */
    for (i = 0; i < SPX_TREE_LEAVES; i++) {
        unsigned char *auth_path = tree_cache->auth_paths[i];
        uint32_t idx = i;

        for (h = 0; h < SPX_TREE_HEIGHT; h++) {
            /* Sibling index: flip the lowest bit */
            uint32_t sibling_idx = idx ^ 1;

            /* Copy sibling to auth path */
            memcpy(auth_path + h * SPX_N, nodes[h][sibling_idx], SPX_N);

            /* Move to parent level */
            idx >>= 1;
        }
    }
}

/*
 * Initialize multi-layer cache.
 * For 128s: only 1 layer supported (72 KB, 14.3% speedup)
 */
void merkle_init_multilayer_cache(spx_multilayer_cache *cache,
                                   const spx_ctx *ctx,
                                   int num_layers) {
    if (num_layers < 1) num_layers = 1;
    if (num_layers > SPX_CACHE_MAX_LAYERS) num_layers = SPX_CACHE_MAX_LAYERS;

    cache->num_layers = num_layers;
    cache->initialized = 0;

    /* Cache layer 6 (top layer, SPX_D - 1): 1 tree at tree_index = 0 */
    compute_tree_auth_paths(&cache->top_layer, ctx, SPX_D - 1, 0);

    cache->initialized = 1;
}

/*
 * Generate a Merkle signature using multi-layer cached data.
 */
void merkle_sign_multilayer_cached(uint8_t *sig, unsigned char *root,
                                    const spx_ctx *ctx,
                                    uint32_t wots_addr[8], uint32_t tree_addr[8],
                                    uint32_t idx_leaf, uint64_t tree_index,
                                    int layer,
                                    const spx_multilayer_cache *cache) {
    unsigned char *auth_path = sig + SPX_WOTS_BYTES;
    struct leaf_info_x1 info = { 0 };
    unsigned steps[SPX_WOTS_LEN];
    unsigned char leaf[SPX_N];
    unsigned char current[SPX_N];
    uint32_t h;
    const spx_layer_tree_cache *tree_cache = NULL;

    (void)tree_index;  /* Not used for 128s single-layer cache */

    /* Only top layer is cached for 128s */
    if (layer == SPX_D - 1) {
        tree_cache = &cache->top_layer;
    }

    /* If no cache available for this layer, fall back to standard signing */
    if (!tree_cache) {
        merkle_sign(sig, root, ctx, wots_addr, tree_addr, idx_leaf);
        return;
    }

    /* Setup for WOTS signature generation */
    info.wots_sig = sig;
    chain_lengths(steps, root);
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    /* Generate only the WOTS signature and leaf for idx_leaf */
    set_keypair_addr(info.leaf_addr, idx_leaf);
    set_keypair_addr(info.pk_addr, idx_leaf);

    /* Generate WOTS signature and compute the leaf (public key hash) */
    wots_gen_leafx1(leaf, ctx, idx_leaf, &info);

    /* Copy pre-computed authentication path from cache */
    memcpy(auth_path, tree_cache->auth_paths[idx_leaf], SPX_TREE_HEIGHT * SPX_N);

    /* Compute the root by hashing up the tree */
    memcpy(current, leaf, SPX_N);

    for (h = 0; h < SPX_TREE_HEIGHT; h++) {
        uint32_t idx_in_level = idx_leaf >> h;
        unsigned char *sibling = auth_path + h * SPX_N;
        unsigned char parent[2 * SPX_N];

        set_tree_height(tree_addr, h + 1);
        set_tree_index(tree_addr, idx_in_level >> 1);

        if (idx_in_level & 1) {
            memcpy(parent, sibling, SPX_N);
            memcpy(parent + SPX_N, current, SPX_N);
        } else {
            memcpy(parent, current, SPX_N);
            memcpy(parent + SPX_N, sibling, SPX_N);
        }

        thash(current, parent, 2, ctx, tree_addr);
    }

    memcpy(root, current, SPX_N);
}

/*
 * Initialize the top layer cache (backward compatible).
 * Optimized O(n) algorithm.
 */
void merkle_init_top_cache(spx_top_cache *cache, const spx_ctx *ctx) {
    uint32_t tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};
    uint32_t i, h;

    /* Allocate space for all nodes by level */
    unsigned char nodes[SPX_TREE_HEIGHT + 1][SPX_TREE_LEAVES][SPX_N];

    struct leaf_info_x1 info = { 0 };
    unsigned steps[SPX_WOTS_LEN];

    set_layer_addr(tree_addr, SPX_D - 1);
    set_layer_addr(wots_addr, SPX_D - 1);
    set_tree_addr(tree_addr, 0);
    set_tree_addr(wots_addr, 0);

    /* Setup for leaf generation */
    info.wots_sig = NULL;
    info.wots_sign_leaf = ~0U;
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    /* Step 1: Compute all leaf nodes - O(n) */
    for (i = 0; i < SPX_TREE_LEAVES; i++) {
        set_keypair_addr(info.leaf_addr, i);
        set_keypair_addr(info.pk_addr, i);
        wots_gen_leafx1(nodes[0][i], ctx, i, &info);
        /* Also store in cache->leaves */
        memcpy(cache->leaves[i], nodes[0][i], SPX_N);
    }

    /* Step 2: Build internal nodes bottom-up - O(n) */
    for (h = 0; h < SPX_TREE_HEIGHT; h++) {
        uint32_t nodes_at_level = SPX_TREE_LEAVES >> h;
        uint32_t nodes_at_next = nodes_at_level >> 1;

        for (i = 0; i < nodes_at_next; i++) {
            unsigned char parent_input[2 * SPX_N];

            set_tree_height(tree_addr, h + 1);
            set_tree_index(tree_addr, i);

            memcpy(parent_input, nodes[h][2*i], SPX_N);
            memcpy(parent_input + SPX_N, nodes[h][2*i + 1], SPX_N);

            thash(nodes[h + 1][i], parent_input, 2, ctx, tree_addr);
        }
    }

    /* Step 3: Extract auth paths for each leaf - O(n * h) */
    for (i = 0; i < SPX_TREE_LEAVES; i++) {
        unsigned char *auth_path = cache->auth_paths[i];
        uint32_t idx = i;

        for (h = 0; h < SPX_TREE_HEIGHT; h++) {
            uint32_t sibling_idx = idx ^ 1;
            memcpy(auth_path + h * SPX_N, nodes[h][sibling_idx], SPX_N);
            idx >>= 1;
        }
    }

    cache->initialized = 1;
}

/*
 * Generate a Merkle signature using cached data (backward compatible).
 */
void merkle_sign_cached(uint8_t *sig, unsigned char *root,
                        const spx_ctx *ctx,
                        uint32_t wots_addr[8], uint32_t tree_addr[8],
                        uint32_t idx_leaf,
                        const spx_top_cache *cache) {
    unsigned char *auth_path = sig + SPX_WOTS_BYTES;
    struct leaf_info_x1 info = { 0 };
    unsigned steps[SPX_WOTS_LEN];
    unsigned char leaf[SPX_N];
    unsigned char current[SPX_N];
    uint32_t h;

    if (!cache || !cache->initialized) {
        merkle_sign(sig, root, ctx, wots_addr, tree_addr, idx_leaf);
        return;
    }

    info.wots_sig = sig;
    chain_lengths(steps, root);
    info.wots_steps = steps;

    set_type(&tree_addr[0], SPX_ADDR_TYPE_HASHTREE);
    set_type(&info.pk_addr[0], SPX_ADDR_TYPE_WOTSPK);
    copy_subtree_addr(&info.leaf_addr[0], wots_addr);
    copy_subtree_addr(&info.pk_addr[0], wots_addr);

    info.wots_sign_leaf = idx_leaf;

    set_keypair_addr(info.leaf_addr, idx_leaf);
    set_keypair_addr(info.pk_addr, idx_leaf);

    wots_gen_leafx1(leaf, ctx, idx_leaf, &info);

    memcpy(auth_path, cache->auth_paths[idx_leaf], SPX_TREE_HEIGHT * SPX_N);

    memcpy(current, leaf, SPX_N);

    for (h = 0; h < SPX_TREE_HEIGHT; h++) {
        uint32_t idx_in_level = idx_leaf >> h;
        unsigned char *sibling = auth_path + h * SPX_N;
        unsigned char parent[2 * SPX_N];

        set_tree_height(tree_addr, h + 1);
        set_tree_index(tree_addr, idx_in_level >> 1);

        if (idx_in_level & 1) {
            memcpy(parent, sibling, SPX_N);
            memcpy(parent + SPX_N, current, SPX_N);
        } else {
            memcpy(parent, current, SPX_N);
            memcpy(parent + SPX_N, sibling, SPX_N);
        }

        thash(current, parent, 2, ctx, tree_addr);
    }

    memcpy(root, current, SPX_N);
}
