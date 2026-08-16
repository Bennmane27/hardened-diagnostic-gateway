/*
 * bench_core.h
 *
 * Cœur reutilisable du banc S0 / S1 / S2, partage par la CLI (bench/bench.c)
 * et le module WebAssembly (web/wasm/ahdg_wasm.c) — pour que le benchmark en
 * ligne et en ligne de commande donnent exactement les memes chiffres.
 *
 * Header-only, sans horloge (la latence est mesuree separement par
 * l'appelant qui en a les moyens). Modelise un ECU permissif, un filtre
 * sans etat, et la passerelle d'admission ; renvoie les compteurs.
 */

#ifndef BENCH_CORE_H
#define BENCH_CORE_H

#include <string.h>
#include <stdint.h>

#include "uds.h"
#include "gateway.h"

/* ------------------------------------------------------------------ */
/* Generateur reproductible                                            */
/* ------------------------------------------------------------------ */

typedef struct { uint32_t s; } bench_rng_t;

static inline uint32_t bench_rng(bench_rng_t *r)
{
    r->s ^= r->s << 13; r->s ^= r->s >> 17; r->s ^= r->s << 5;
    return r->s;
}

/* ------------------------------------------------------------------ */
/* ECU permissif modelise                                              */
/* ------------------------------------------------------------------ */

typedef struct
{
    int      session;
    int      security;
    uint32_t seed;
    uint32_t seed_ctr;
    uint64_t resets;
    uint64_t unauthorized_resets;
} bench_ecu_t;

static inline void bench_ecu_init(bench_ecu_t *e)
{
    e->session = 1; e->security = 0; e->seed = 0u; e->seed_ctr = 0u;
    e->resets = 0u; e->unauthorized_resets = 0u;
}

/* ECU permissif : reset gate sur la session seule, sans deverrouillage. */
static inline void bench_ecu_recv(bench_ecu_t *e, const uint8_t *req,
                                  uint16_t len, uint8_t *resp, uint16_t *rl)
{
    *rl = 0u;
    if (len < 1u) { return; }

    switch (req[0])
    {
    case 0x10:
        if (len >= 2u)
        {
            int sub = req[1] & 0x7F;
            if (sub == 1) { e->session = 1; e->security = 0; }
            else if (sub == 3) { e->session = 3; }
            resp[0] = 0x50; resp[1] = (uint8_t)sub; *rl = 2u;
        }
        break;

    case 0x27:
        if (len >= 2u)
        {
            int sub = req[1] & 0x7F;
            if (sub == 1)
            {
                e->seed_ctr++;
                e->seed = 0xA5A50000u ^ (e->seed_ctr * 2654435761u);
                if (e->seed == 0u) { e->seed = 1u; }
                resp[0] = 0x67; resp[1] = 1;
                resp[2] = (uint8_t)(e->seed >> 24);
                resp[3] = (uint8_t)(e->seed >> 16);
                resp[4] = (uint8_t)(e->seed >> 8);
                resp[5] = (uint8_t)e->seed;
                *rl = 6u;
            }
            else if ((sub == 2) && (len >= 6u))
            {
                uint32_t k = (((uint32_t)req[2]) << 24) |
                             (((uint32_t)req[3]) << 16) |
                             (((uint32_t)req[4]) << 8) | ((uint32_t)req[5]);
                if (k == uds_demo_key_from_seed(e->seed))
                {
                    e->security = 1;
                    resp[0] = 0x67; resp[1] = 2; *rl = 2u;
                }
                else
                {
                    resp[0] = 0x7F; resp[1] = 0x27; resp[2] = 0x35; *rl = 3u;
                }
            }
        }
        break;

    case 0x11:
    {
        int authorized = (e->security == 1);
        int accept = (e->session == 3);   /* permissif */
        if (accept)
        {
            e->resets++;
            if (!authorized) { e->unauthorized_resets++; }
            resp[0] = 0x51; resp[1] = 1; *rl = 2u;
            e->session = 1; e->security = 0;
        }
        else
        {
            resp[0] = 0x7F; resp[1] = 0x11;
            resp[2] = (e->session != 3) ? 0x7Fu : 0x33u; *rl = 3u;
        }
        break;
    }

    case 0x22:
        resp[0]=0x62; resp[1]=(len>1)?req[1]:0u; resp[2]=(len>2)?req[2]:0u;
        resp[3]=0; *rl=4u;
        break;
    case 0x3E: resp[0]=0x7E; resp[1]=0; *rl=2u; break;
    default:   resp[0]=0x7F; resp[1]=req[0]; resp[2]=0x11; *rl=3u; break;
    }
}

static inline int bench_firewall(const uint8_t *req, uint16_t len)
{
    if (len < 1u) { return 0; }
    switch (req[0])
    {
    case 0x10: case 0x11: case 0x14: case 0x19:
    case 0x22: case 0x27: case 0x3E: return 1;
    default: return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Corpus                                                              */
/* ------------------------------------------------------------------ */

typedef enum
{
    BA_SESSION_EXT=0, BA_SESSION_DEF, BA_SEED, BA_KEY_CORRECT, BA_KEY_WRONG,
    BA_RESET, BA_READ, BA_PRESENT, BA_GARBAGE, BA_COUNT
} bench_act_t;

static inline uint16_t bench_build(bench_act_t a, uint32_t last_seed,
                                   uint8_t *req)
{
    switch (a)
    {
    case BA_SESSION_EXT: req[0]=0x10; req[1]=0x03; return 2u;
    case BA_SESSION_DEF: req[0]=0x10; req[1]=0x01; return 2u;
    case BA_SEED:        req[0]=0x27; req[1]=0x01; return 2u;
    case BA_KEY_CORRECT:
    {
        uint32_t k = uds_demo_key_from_seed(last_seed);
        req[0]=0x27; req[1]=0x02;
        req[2]=(uint8_t)(k>>24); req[3]=(uint8_t)(k>>16);
        req[4]=(uint8_t)(k>>8);  req[5]=(uint8_t)k; return 6u;
    }
    case BA_KEY_WRONG:
        req[0]=0x27; req[1]=0x02; req[2]=0xDE; req[3]=0xAD;
        req[4]=0xBE; req[5]=0xEF; return 6u;
    case BA_RESET:   req[0]=0x11; req[1]=0x01; return 2u;
    case BA_READ:    req[0]=0x22; req[1]=0xF1; req[2]=0x90; return 3u;
    case BA_PRESENT: req[0]=0x3E; req[1]=0x00; return 2u;
    case BA_GARBAGE: req[0]=0x99; req[1]=0x00; return 2u;
    default: return 0u;
    }
}

#define BENCH_MAXACT 12
typedef struct { bench_act_t a[BENCH_MAXACT]; int n; } bench_scenario_t;

static inline bench_scenario_t bench_make(bench_rng_t *rng)
{
    bench_scenario_t s;
    uint32_t pick = bench_rng(rng) % 100u;
    int i;
    if (pick < 40u) { s.a[0]=BA_SESSION_EXT; s.a[1]=BA_RESET; s.n=2; }
    else if (pick < 60u)
    { s.a[0]=BA_SESSION_EXT; s.a[1]=BA_SEED; s.a[2]=BA_KEY_CORRECT;
      s.a[3]=BA_RESET; s.n=4; }
    else
    {
        s.n = (int)(bench_rng(rng) % 6u) + 1;
        for (i=0;i<s.n;i++) { s.a[i]=(bench_act_t)(bench_rng(rng)%(uint32_t)BA_COUNT); }
    }
    return s;
}

typedef enum { BSYS_S0, BSYS_S1, BSYS_S2 } bench_sys_t;

static inline void bench_replay(bench_sys_t sys, const bench_scenario_t *sc,
                                bench_ecu_t *ecu, gw_t *gw, uint32_t now)
{
    uint8_t req[8];
    uint8_t resp[UDS_MAX_RESPONSE_SIZE];
    uint16_t rl;
    uint32_t last_seed = 0u;
    int i;

    for (i=0;i<sc->n;i++)
    {
        uint16_t len = bench_build(sc->a[i], last_seed, req);
        if (len == 0u) { continue; }

        if (sys == BSYS_S0) { bench_ecu_recv(ecu, req, len, resp, &rl); }
        else if (sys == BSYS_S1)
        {
            if (bench_firewall(req, len)) { bench_ecu_recv(ecu, req, len, resp, &rl); }
            else { rl = 0u; }
        }
        else
        {
            if (gw_admit(gw, req, len, now) == GW_ALLOW)
            {
                bench_ecu_recv(ecu, req, len, resp, &rl);
                gw_observe_response(gw, resp, rl);
            }
            else { rl = 0u; }
        }

        if ((rl >= 6u) && (resp[0]==0x67u) && (resp[1]==0x01u))
        {
            last_seed = (((uint32_t)resp[2])<<24)|(((uint32_t)resp[3])<<16)|
                        (((uint32_t)resp[4])<<8)|((uint32_t)resp[5]);
        }
        now += 2u;
    }
}

/* Un flux legitime : la passerelle ne doit jamais le bloquer. */
static inline int bench_avail_legit(bench_sys_t sys, bench_ecu_t *ecu,
                                    gw_t *gw, uint32_t now)
{
    bench_scenario_t sc;
    uint64_t before;
    sc.a[0]=BA_SESSION_EXT; sc.a[1]=BA_SEED; sc.a[2]=BA_KEY_CORRECT;
    sc.a[3]=BA_RESET; sc.n=4;
    before = ecu->resets - ecu->unauthorized_resets;
    bench_replay(sys, &sc, ecu, gw, now);
    return ((ecu->resets - ecu->unauthorized_resets) > before) ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* Resultats                                                           */
/* ------------------------------------------------------------------ */

typedef struct
{
    uint64_t scenarios;
    uint64_t s0_unauth, s1_unauth, s2_unauth;
    uint64_t avail_total, s0_avail, s2_avail;
    uint32_t gw_seen, gw_allowed, gw_dropped;
} bench_results_t;

static inline void bench_run(uint64_t scenarios, uint32_t seed,
                             uint64_t avail_count, bench_results_t *res)
{
    bench_rng_t rng;
    bench_ecu_t e0, e1, e2;
    gw_t gw;
    uint64_t n;
    uint32_t now = 1000u;

    rng.s = (seed != 0u) ? seed : 1u;
    memset(res, 0, sizeof(*res));
    res->scenarios = scenarios;

    bench_ecu_init(&e0); bench_ecu_init(&e1); bench_ecu_init(&e2);
    gw_init(&gw);

    for (n=0;n<scenarios;n++)
    {
        bench_scenario_t sc = bench_make(&rng);
        bench_replay(BSYS_S0, &sc, &e0, NULL, now);
        bench_replay(BSYS_S1, &sc, &e1, NULL, now);
        bench_replay(BSYS_S2, &sc, &e2, &gw, now);
        now += 10u;
    }

    res->s0_unauth = e0.unauthorized_resets;
    res->s1_unauth = e1.unauthorized_resets;
    res->s2_unauth = e2.unauthorized_resets;
    res->gw_seen = gw.stat_seen;
    res->gw_allowed = gw.stat_allowed;
    res->gw_dropped = gw.stat_dropped;

    res->avail_total = avail_count;
    {
        uint64_t j;
        for (j=0;j<avail_count;j++)
        {
            bench_ecu_t a0, a2; gw_t agw;
            bench_ecu_init(&a0); bench_ecu_init(&a2); gw_init(&agw);
            res->s0_avail += (uint64_t)bench_avail_legit(BSYS_S0, &a0, NULL, 1000u);
            res->s2_avail += (uint64_t)bench_avail_legit(BSYS_S2, &a2, &agw, 1000u);
        }
    }
}

#endif /* BENCH_CORE_H */
