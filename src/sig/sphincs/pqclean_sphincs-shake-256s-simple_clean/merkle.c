#include <stdint.h>
#include <string.h>

#include "address.h"
#include "merkle.h"
#include "params.h"
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
 * Multi-Layer Cache Implementation
 *============================================================================*/

#include "thash.h"

/*
 * Helper function to compute auth paths for a single tree at a given layer.
 * Stores all 256 auth paths for leaves 0-255.
 */
static void compute_tree_auth_paths(spx_layer_tree_cache *tree_cache,
                                     const spx_ctx *ctx,
                                     int layer,
                                     uint64_t tree_index) {
    uint32_t tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};
    unsigned char sig_buffer[SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N];
    unsigned char root[SPX_N];
    uint32_t i;

    set_layer_addr(tree_addr, layer);
    set_layer_addr(wots_addr, layer);
    set_tree_addr(tree_addr, tree_index);
    set_tree_addr(wots_addr, tree_index);

    /* For each possible leaf index, compute the authentication path */
    for (i = 0; i < SPX_TREE_LEAVES; i++) {
        merkle_sign(sig_buffer, root, ctx, wots_addr, tree_addr, i);
        /* Extract the authentication path (after WOTS signature) */
        memcpy(tree_cache->auth_paths[i], sig_buffer + SPX_WOTS_BYTES,
               SPX_TREE_HEIGHT * SPX_N);
    }
}

/*
 * Initialize multi-layer cache.
 * For 256s, only 1 layer is practical due to large tree size (256 leaves).
 */
void merkle_init_multilayer_cache(spx_multilayer_cache *cache,
                                   const spx_ctx *ctx,
                                   int num_layers) {
    if (num_layers < 1) num_layers = 1;
    if (num_layers > SPX_CACHE_MAX_LAYERS) num_layers = SPX_CACHE_MAX_LAYERS;

    cache->num_layers = num_layers;
    cache->initialized = 0;

    /* Cache layer 7 (top layer, SPX_D - 1): 1 tree at tree_index = 0 */
    compute_tree_auth_paths(&cache->top_layer, ctx, SPX_D - 1, 0);

    cache->initialized = 1;
}

/*
 * Generate a Merkle signature using multi-layer cached data.
 * Only computes the WOTS signature; uses cached auth path.
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

    (void)tree_index;  /* Unused for 256s single-layer cache */

    /* Determine which cache to use based on layer */
    if (layer == SPX_D - 1) {
        /* Top layer */
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
 * Initialize the top layer cache (backward compatible, 1 layer only).
 */
void merkle_init_top_cache(spx_top_cache *cache, const spx_ctx *ctx) {
    uint32_t top_tree_addr[8] = {0};
    uint32_t wots_addr[8] = {0};
    unsigned char sig_buffer[SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N];
    unsigned char root[SPX_N];
    uint32_t i;

    set_layer_addr(top_tree_addr, SPX_D - 1);
    set_layer_addr(wots_addr, SPX_D - 1);

    for (i = 0; i < SPX_TREE_LEAVES; i++) {
        set_tree_addr(top_tree_addr, 0);
        set_tree_addr(wots_addr, 0);

        merkle_sign(sig_buffer, root, ctx, wots_addr, top_tree_addr, i);

        memcpy(cache->auth_paths[i], sig_buffer + SPX_WOTS_BYTES,
               SPX_TREE_HEIGHT * SPX_N);
    }

    for (i = 0; i < SPX_TREE_LEAVES; i += 2) {
        memcpy(cache->leaves[i + 1], cache->auth_paths[i], SPX_N);
        memcpy(cache->leaves[i], cache->auth_paths[i + 1], SPX_N);
    }

    cache->initialized = 1;
}

/*
 * Generate a Merkle signature using cached data.
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
