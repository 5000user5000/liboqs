#ifndef SPHINCS_TIMING_H
#define SPHINCS_TIMING_H

#include <time.h>
#include <stdio.h>

typedef struct {
    struct timespec start;
    struct timespec end;
    double elapsed_ns;
} timing_ctx;

static inline void timing_start(timing_ctx *ctx) {
    clock_gettime(CLOCK_MONOTONIC, &ctx->start);
}

static inline void timing_end(timing_ctx *ctx) {
    clock_gettime(CLOCK_MONOTONIC, &ctx->end);
    ctx->elapsed_ns = (ctx->end.tv_sec - ctx->start.tv_sec) * 1000000000.0 +
                      (ctx->end.tv_nsec - ctx->start.tv_nsec);
}

static inline double timing_get_ms(timing_ctx *ctx) {
    return ctx->elapsed_ns / 1000000.0;
}

static inline double timing_get_us(timing_ctx *ctx) {
    return ctx->elapsed_ns / 1000.0;
}

typedef struct {
    timing_ctx preprocessing;
    timing_ctx fors_signing;
    timing_ctx merkle_signing;
    timing_ctx total;
} sphincs_timing_ctx;

static inline void print_timing_results(sphincs_timing_ctx *timing) {
    printf("SPHINCS+-SHAKE-256s-simple Signing Timing Results:\n");
    printf("  Preprocessing:   %.6f ms (%.3f us)\n",
           timing_get_ms(&timing->preprocessing), timing_get_us(&timing->preprocessing));
    printf("  FORS Signing:    %.6f ms (%.3f us)\n",
           timing_get_ms(&timing->fors_signing), timing_get_us(&timing->fors_signing));
    printf("  Merkle Signing:  %.6f ms (%.3f us)\n",
           timing_get_ms(&timing->merkle_signing), timing_get_us(&timing->merkle_signing));
    printf("  Total Signing:   %.6f ms (%.3f us)\n",
           timing_get_ms(&timing->total), timing_get_us(&timing->total));
    printf("  Percentage breakdown:\n");
    double total_time = timing_get_ms(&timing->total);
    if (total_time > 0) {
        printf("    Preprocessing:   %.1f%%\n", (timing_get_ms(&timing->preprocessing) / total_time) * 100);
        printf("    FORS Signing:    %.1f%%\n", (timing_get_ms(&timing->fors_signing) / total_time) * 100);
        printf("    Merkle Signing:  %.1f%%\n", (timing_get_ms(&timing->merkle_signing) / total_time) * 100);
    }
}

#endif /* SPHINCS_TIMING_H */