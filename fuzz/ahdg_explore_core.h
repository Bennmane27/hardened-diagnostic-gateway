/*
 * ahdg_explore_core.h
 *
 * Cœur reutilisable de l'explorateur adversarial de l'espace d'etats UDS.
 *
 * Extrait de fuzz/ahdg_explore.c pour etre partage par deux consommateurs :
 *   - la CLI (fuzz/ahdg_explore.c) ;
 *   - le module WebAssembly (web/wasm/ahdg_wasm.c), qui fait tourner le
 *     MEME adversaire dans le navigateur.
 *
 * Une seule source de verite pour l'attaquant : la CLI et le simulateur en
 * ligne ne peuvent pas diverger. Header-only (static inline), inclus dans
 * un seul .c par binaire.
 *
 * L'attaquant ne produit AUCUNE sortie : il remplit une structure de
 * resultats. La mise en forme (texte pour la CLI, JSON pour le web) est la
 * responsabilite de l'appelant.
 */

#ifndef AHDG_EXPLORE_CORE_H
#define AHDG_EXPLORE_CORE_H

#include <string.h>
#include <stdint.h>

#include "uds.h"
#include "invariants.h"

#define AHDG_MAX_SEQ 64

/* ------------------------------------------------------------------ */
/* Generateur reproductible                                            */
/* ------------------------------------------------------------------ */

typedef struct { uint32_t s; } ahdg_rng_t;

static inline uint32_t ahdg_rng_next(ahdg_rng_t *r)
{
    r->s ^= r->s << 13;
    r->s ^= r->s >> 17;
    r->s ^= r->s << 5;
    return r->s;
}

/* ------------------------------------------------------------------ */
/* Fournisseurs applicatifs factices, deterministes                    */
/* ------------------------------------------------------------------ */

static inline uds_result_t ahdg_did_read(uint16_t did, uint8_t *out,
                                         uint16_t cap, uint16_t *len,
                                         void *ctx)
{
    (void)ctx;
    if (cap < 2u) { return UDS_ERR_BUFFER_TOO_SMALL; }
    out[0] = (uint8_t)(did >> 8);
    out[1] = (uint8_t)did;
    *len = 2u;
    return UDS_OK;
}

static inline uds_result_t ahdg_dtc_read(uint8_t mask, uint8_t *out,
                                         uint16_t cap, uint16_t *len,
                                         void *ctx)
{
    (void)mask; (void)out; (void)cap; (void)ctx;
    *len = 0u;
    return UDS_OK;
}

static inline uds_result_t ahdg_dtc_clear(uint32_t group, void *ctx)
{
    (void)ctx;
    return (group == 0xFFFFFFu) ? UDS_OK : UDS_ERR_DID_NOT_FOUND;
}

static inline uds_result_t ahdg_ecu_reset(uint8_t type, void *ctx)
{
    (void)type; (void)ctx;
    return UDS_OK;
}

/* ------------------------------------------------------------------ */
/* Alphabet d'actions                                                  */
/* ------------------------------------------------------------------ */

typedef enum
{
    AHDG_SESSION_DEFAULT = 0,
    AHDG_SESSION_EXTENDED,
    AHDG_SESSION_PROGRAMMING,
    AHDG_READ_DID,
    AHDG_TESTER_PRESENT,
    AHDG_SEED_REQUEST,
    AHDG_KEY_CORRECT,
    AHDG_KEY_WRONG,
    AHDG_KEY_REPLAY,
    AHDG_ECU_RESET,
    AHDG_CLEAR_DTC,
    AHDG_CLOCK_PAST_S3,
    AHDG_CLOCK_SMALL,
    AHDG_CLOCK_PAST_LOCKOUT,
    AHDG_ACT_COUNT
} ahdg_action_t;

static inline const char *ahdg_action_name(ahdg_action_t a)
{
    switch (a)
    {
    case AHDG_SESSION_DEFAULT:     return "session default (10 01)";
    case AHDG_SESSION_EXTENDED:    return "session extended (10 03)";
    case AHDG_SESSION_PROGRAMMING: return "session programming (10 02)";
    case AHDG_READ_DID:            return "read DID (22 F1 90)";
    case AHDG_TESTER_PRESENT:      return "tester present (3E 00)";
    case AHDG_SEED_REQUEST:        return "request seed (27 01)";
    case AHDG_KEY_CORRECT:         return "send correct key (27 02, legit)";
    case AHDG_KEY_WRONG:           return "send wrong key (27 02)";
    case AHDG_KEY_REPLAY:          return "replay last key (27 02)";
    case AHDG_ECU_RESET:           return "ECU reset (11 01)";
    case AHDG_CLEAR_DTC:           return "clear DTC (14 FF FF FF)";
    case AHDG_CLOCK_PAST_S3:       return "clock += S3 timeout";
    case AHDG_CLOCK_SMALL:         return "clock += small";
    case AHDG_CLOCK_PAST_LOCKOUT:  return "clock += lockout";
    default:                       return "?";
    }
}

typedef struct
{
    uint32_t clock;
    uint8_t  last_key[4];
    int      have_last_key;
} ahdg_attacker_t;

typedef struct
{
    uds_session_t session;
    uint8_t security_level;
    uint8_t seed_pending;
    uint8_t failed_attempts;
    uint8_t locked_out;
} ahdg_snap_t;

static inline ahdg_snap_t ahdg_snapshot(const uds_context_t *ctx)
{
    ahdg_snap_t s;
    s.session         = ctx->session;
    s.security_level  = ctx->security_level;
    s.seed_pending    = ctx->seed_pending;
    s.failed_attempts = ctx->failed_attempts;
    s.locked_out      = ctx->locked_out;
    return s;
}

static inline void ahdg_reset_ctx(uds_context_t *ctx, ahdg_attacker_t *atk)
{
    uds_init(ctx);
    uds_set_did_provider(ctx, ahdg_did_read, NULL);
    uds_set_dtc_provider(ctx, ahdg_dtc_read, ahdg_dtc_clear);
    uds_set_reset_handler(ctx, ahdg_ecu_reset);
    atk->clock = 1000u;
    atk->have_last_key = 0;
    memset(atk->last_key, 0, sizeof(atk->last_key));
}

static inline void ahdg_apply(uds_context_t *ctx, ahdg_attacker_t *atk,
                              ahdg_action_t a, uint8_t *resp, uint16_t *rlen)
{
    uint8_t req[8];
    uint16_t req_len = 0u;
    *rlen = 0u;

    switch (a)
    {
    case AHDG_SESSION_DEFAULT:     req[0]=0x10; req[1]=0x01; req_len=2u; break;
    case AHDG_SESSION_EXTENDED:    req[0]=0x10; req[1]=0x03; req_len=2u; break;
    case AHDG_SESSION_PROGRAMMING: req[0]=0x10; req[1]=0x02; req_len=2u; break;
    case AHDG_READ_DID:  req[0]=0x22; req[1]=0xF1; req[2]=0x90; req_len=3u; break;
    case AHDG_TESTER_PRESENT: req[0]=0x3E; req[1]=0x00; req_len=2u; break;
    case AHDG_SEED_REQUEST:   req[0]=0x27; req[1]=0x01; req_len=2u; break;

    case AHDG_KEY_CORRECT:
    {
        uint32_t key = uds_demo_key_from_seed(ctx->current_seed);
        req[0]=0x27; req[1]=0x02;
        req[2]=(uint8_t)(key>>24); req[3]=(uint8_t)(key>>16);
        req[4]=(uint8_t)(key>>8);  req[5]=(uint8_t)key; req_len=6u;
        atk->last_key[0]=req[2]; atk->last_key[1]=req[3];
        atk->last_key[2]=req[4]; atk->last_key[3]=req[5];
        atk->have_last_key=1;
        break;
    }
    case AHDG_KEY_WRONG:
        req[0]=0x27; req[1]=0x02;
        req[2]=0xDE; req[3]=0xAD; req[4]=0xBE; req[5]=0xEF; req_len=6u;
        atk->last_key[0]=0xDE; atk->last_key[1]=0xAD;
        atk->last_key[2]=0xBE; atk->last_key[3]=0xEF; atk->have_last_key=1;
        break;
    case AHDG_KEY_REPLAY:
        req[0]=0x27; req[1]=0x02;
        req[2]=atk->have_last_key?atk->last_key[0]:0u;
        req[3]=atk->have_last_key?atk->last_key[1]:0u;
        req[4]=atk->have_last_key?atk->last_key[2]:0u;
        req[5]=atk->have_last_key?atk->last_key[3]:0u; req_len=6u;
        break;

    case AHDG_ECU_RESET:  req[0]=0x11; req[1]=0x01; req_len=2u; break;
    case AHDG_CLEAR_DTC:
        req[0]=0x14; req[1]=0xFF; req[2]=0xFF; req[3]=0xFF; req_len=4u; break;

    case AHDG_CLOCK_PAST_S3:
        atk->clock += (UDS_S3_SERVER_TIMEOUT_MS + 10u);
        uds_poll(ctx, atk->clock); return;
    case AHDG_CLOCK_SMALL:
        atk->clock += 5u; uds_poll(ctx, atk->clock); return;
    case AHDG_CLOCK_PAST_LOCKOUT:
        atk->clock += (UDS_SECURITY_LOCKOUT_MS + 10u);
        uds_poll(ctx, atk->clock); return;
    default: return;
    }

    (void)uds_handle_request(ctx, req, req_len, atk->clock, resp, 64, rlen);
}

/* Renvoie l'ID de l'invariant viole, ou -1. Conservateur. */
static inline int ahdg_check(const ahdg_snap_t *pre, const uds_context_t *post,
                             ahdg_action_t a, const uint8_t *resp, uint16_t rl)
{
    int positive_reset = (rl >= 1u) && (resp[0] == 0x51u);
    int positive_key   = (rl >= 2u) && (resp[0] == 0x67u) && (resp[1] == 0x02u);

    if (positive_reset && (pre->security_level == UDS_SECURITY_LOCKED))
        return HDG_INV_SEC_NO_UNAUTH_EFFECT;
    if (positive_key && (pre->seed_pending == 0u))
        return HDG_INV_SEC_SEED_KEY_BINDING;
    if (positive_reset && (post->security_level != UDS_SECURITY_LOCKED))
        return HDG_INV_SEC_RELOCK_ON_RESET;
    if (positive_reset && (post->seed_pending != 0u))
        return HDG_INV_XL_NO_AUTHORITY_CARRYOVER;
    if ((post->session == UDS_SESSION_DEFAULT) &&
        (post->security_level != UDS_SECURITY_LOCKED))
        return HDG_INV_SEC_RELOCK_ON_DEFAULT;
    if ((post->failed_attempts < pre->failed_attempts) && (positive_key == 0) &&
        (a != AHDG_CLOCK_PAST_LOCKOUT) &&
        !((pre->locked_out != 0u) && (post->locked_out == 0u)))
        return HDG_INV_SEC_MONOTONIC_ATTEMPTS;
    return -1;
}

static inline int ahdg_replay(const ahdg_action_t *seq, int len)
{
    uds_context_t ctx;
    ahdg_attacker_t atk;
    int i;
    ahdg_reset_ctx(&ctx, &atk);
    for (i = 0; i < len; i++)
    {
        uint8_t resp[64];
        uint16_t rl = 0u;
        ahdg_snap_t pre = ahdg_snapshot(&ctx);
        int v;
        ahdg_apply(&ctx, &atk, seq[i], resp, &rl);
        v = ahdg_check(&pre, &ctx, seq[i], resp, rl);
        if (v >= 0) { return v; }
    }
    return -1;
}

static inline int ahdg_minimize(ahdg_action_t *seq, int len, int target)
{
    int changed = 1;
    while (changed != 0)
    {
        int i;
        changed = 0;
        for (i = 0; i < len; i++)
        {
            ahdg_action_t tmp[AHDG_MAX_SEQ] = {0};
            int tlen = 0, j;
            for (j = 0; j < len; j++) { if (j != i) { tmp[tlen++] = seq[j]; } }
            if (ahdg_replay(tmp, tlen) == target)
            {
                for (j = 0; j < tlen; j++) { seq[j] = tmp[j]; }
                len = tlen; changed = 1; i--;
            }
        }
    }
    return len;
}

/* ------------------------------------------------------------------ */
/* Resultats                                                           */
/* ------------------------------------------------------------------ */

/* Les six invariants evaluables sans la couche transport. */
static const int AHDG_EVALUATED[] = {
    HDG_INV_SEC_NO_UNAUTH_EFFECT,
    HDG_INV_SEC_SEED_KEY_BINDING,
    HDG_INV_SEC_RELOCK_ON_RESET,
    HDG_INV_SEC_RELOCK_ON_DEFAULT,
    HDG_INV_SEC_MONOTONIC_ATTEMPTS,
    HDG_INV_XL_NO_AUTHORITY_CARRYOVER
};
#define AHDG_EVALUATED_COUNT \
    (int)(sizeof(AHDG_EVALUATED) / sizeof(AHDG_EVALUATED[0]))

typedef struct
{
    uint64_t      tested;
    int           states;
    int           found[HDG_INV_COUNT];
    ahdg_action_t cex[HDG_INV_COUNT][AHDG_MAX_SEQ];
    int           cex_len[HDG_INV_COUNT];
} ahdg_results_t;

static inline void ahdg_run(uint64_t budget, uint32_t seed, int max_len,
                            ahdg_results_t *res)
{
    ahdg_rng_t rng;
    uint8_t seen[512];
    uint64_t n;
    int i;

    if (max_len < 1) { max_len = 1; }
    if (max_len > AHDG_MAX_SEQ) { max_len = AHDG_MAX_SEQ; }

    rng.s = (seed != 0u) ? seed : 1u;
    memset(seen, 0, sizeof(seen));
    memset(res, 0, sizeof(*res));

    for (n = 0u; n < budget; n++)
    {
        uds_context_t ctx;
        ahdg_attacker_t atk;
        ahdg_action_t seq[AHDG_MAX_SEQ];
        int len = (int)(ahdg_rng_next(&rng) % (uint32_t)max_len) + 1;
        int step;

        ahdg_reset_ctx(&ctx, &atk);
        res->tested++;

        for (step = 0; step < len; step++)
        {
            uint8_t resp[64];
            uint16_t rl = 0u;
            ahdg_snap_t pre = ahdg_snapshot(&ctx);
            ahdg_action_t a =
                (ahdg_action_t)(ahdg_rng_next(&rng) % (uint32_t)AHDG_ACT_COUNT);
            uint32_t h;
            int v;

            seq[step] = a;
            ahdg_apply(&ctx, &atk, a, resp, &rl);

            h = ((uint32_t)ctx.session) ^ ((uint32_t)ctx.security_level << 3) ^
                ((uint32_t)ctx.seed_pending << 6) ^
                ((uint32_t)ctx.locked_out << 7) ^
                ((uint32_t)ctx.failed_attempts << 8);
            if (seen[h % 512u] == 0u) { seen[h % 512u] = 1u; res->states++; }

            v = ahdg_check(&pre, &ctx, a, resp, rl);
            if (v >= 0)
            {
                if (res->found[v] == 0)
                {
                    int mlen = ahdg_minimize(seq, step + 1, v);
                    res->found[v] = 1;
                    res->cex_len[v] = mlen;
                    for (i = 0; i < mlen; i++) { res->cex[v][i] = seq[i]; }
                }
                break;
            }
        }
    }
}

#endif /* AHDG_EXPLORE_CORE_H */
