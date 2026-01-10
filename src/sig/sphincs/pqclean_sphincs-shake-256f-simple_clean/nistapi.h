#ifndef SPX_API_H
#define SPX_API_H

#include <stddef.h>
#include <stdint.h>

#include "params.h"

#define CRYPTO_ALGNAME "SPHINCS+"

#define CRYPTO_SECRETKEYBYTES SPX_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES SPX_PK_BYTES
#define CRYPTO_BYTES SPX_BYTES
#define CRYPTO_SEEDBYTES (3*SPX_N)

/*
 * Returns the length of a secret key, in bytes
 */
#define crypto_sign_secretkeybytes SPX_NAMESPACE(crypto_sign_secretkeybytes)
size_t crypto_sign_secretkeybytes(void);

/*
 * Returns the length of a public key, in bytes
 */
#define crypto_sign_publickeybytes SPX_NAMESPACE(crypto_sign_publickeybytes)
size_t crypto_sign_publickeybytes(void);

/*
 * Returns the length of a signature, in bytes
 */
#define crypto_sign_bytes SPX_NAMESPACE(crypto_sign_bytes)
size_t crypto_sign_bytes(void);

/*
 * Returns the length of the seed required to generate a key pair, in bytes
 */
#define crypto_sign_seedbytes SPX_NAMESPACE(crypto_sign_seedbytes)
size_t crypto_sign_seedbytes(void);

/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
#define crypto_sign_seed_keypair SPX_NAMESPACE(crypto_sign_seed_keypair)
int crypto_sign_seed_keypair(uint8_t *pk, uint8_t *sk,
                             const uint8_t *seed);

/*
 * Generates a SPHINCS+ key pair.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
#define crypto_sign_keypair SPX_NAMESPACE(crypto_sign_keypair)
int crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

/**
 * Returns an array containing a detached signature.
 */
#define crypto_sign_signature SPX_NAMESPACE(crypto_sign_signature)
int crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen, const uint8_t *sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
#define crypto_sign_verify SPX_NAMESPACE(crypto_sign_verify)
int crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen, const uint8_t *pk);

/**
 * Returns an array containing the signature followed by the message.
 */
#define crypto_sign SPX_NAMESPACE(crypto_sign)
int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk);

/**
 * Verifies a given signature-message pair under a given public key.
 */
#define crypto_sign_open SPX_NAMESPACE(crypto_sign_open)
int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk);

/*============================================================================
 * Multi-Layer Cache Support (Method 2: Static Top-Layer Caching)
 *============================================================================*/

#include "merkle.h"  /* For cache types */

/**
 * Initialize multi-layer cache (1 or 2 layers).
 *
 * @param cache     Pointer to cache structure
 * @param sk        Secret key
 * @param num_layers Number of layers to cache (1 or 2)
 *
 * Space requirements (SPHINCS+-256f):
 *   1 layer:  ~2 KB,  ~5% speedup
 *   2 layers: ~34 KB, ~12% speedup
 */
#define crypto_sign_init_multilayer_cache SPX_NAMESPACE(crypto_sign_init_multilayer_cache)
int crypto_sign_init_multilayer_cache(spx_multilayer_cache *cache,
                                       const uint8_t *sk,
                                       int num_layers);

/**
 * Returns a detached signature using multi-layer cache.
 * Optimizes top 1-2 layers of the hypertree.
 */
#define crypto_sign_signature_multilayer_cached SPX_NAMESPACE(crypto_sign_signature_multilayer_cached)
int crypto_sign_signature_multilayer_cached(uint8_t *sig, size_t *siglen,
                                             const uint8_t *m, size_t mlen,
                                             const uint8_t *sk,
                                             const spx_multilayer_cache *cache);

/* Backward compatible single-layer cache API */

/**
 * Initialize the top layer cache (1 layer only).
 * Should be called once after key generation or loading.
 */
#define crypto_sign_init_cache SPX_NAMESPACE(crypto_sign_init_cache)
int crypto_sign_init_cache(spx_top_cache *cache, const uint8_t *sk);

/**
 * Returns a detached signature using cached top layer.
 * Reduces top layer computation by ~90% compared to standard signing.
 */
#define crypto_sign_signature_cached SPX_NAMESPACE(crypto_sign_signature_cached)
int crypto_sign_signature_cached(uint8_t *sig, size_t *siglen,
                                 const uint8_t *m, size_t mlen,
                                 const uint8_t *sk,
                                 const spx_top_cache *cache);

#endif
