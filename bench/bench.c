/*
 * bench.c
 *
 * CLI du banc S0 / S1 / S2. La logique vit dans bench_core.h, partagee avec
 * le module WebAssembly pour que la CLI et le simulateur en ligne donnent
 * exactement les memes chiffres. Voir docs/findings/BENCH-S0-S1-S2.md.
 *
 * Build : make bench
 */

#define _POSIX_C_SOURCE 199309L   /* clock_gettime, CLOCK_MONOTONIC */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "bench_core.h"

/* Micro-mesure isolee de la latence d'admission de la passerelle. */
static uint64_t measure_admit_ns(uint32_t seed)
{
    gw_t gw;
    bench_rng_t rng;
    struct timespec t0, t1;
    uint64_t calls = 0u;
    int i;

    gw_init(&gw);
    rng.s = (seed != 0u) ? seed : 1u;

    (void)clock_gettime(CLOCK_MONOTONIC, &t0);
    for (i = 0; i < 200000; i++)
    {
        uint8_t req[8];
        bench_scenario_t sc = bench_make(&rng);
        int j;
        uint32_t last_seed = 0u;
        for (j = 0; j < sc.n; j++)
        {
            uint16_t len = bench_build(sc.a[j], last_seed, req);
            if (len == 0u) { continue; }
            (void)gw_admit(&gw, req, len, 1000u);
            calls++;
        }
    }
    (void)clock_gettime(CLOCK_MONOTONIC, &t1);

    {
        uint64_t ns = (uint64_t)((t1.tv_sec - t0.tv_sec) * 1000000000L +
                                 (t1.tv_nsec - t0.tv_nsec));
        return (calls > 0u) ? (ns / calls) : 0u;
    }
}

int main(int argc, char **argv)
{
    uint64_t scenarios = 200000u;
    uint32_t seed = 0xB0A7;
    bench_results_t r;

    if (argc > 1) { scenarios = strtoull(argv[1], NULL, 10); }
    if (argc > 2) { seed = (uint32_t)strtoul(argv[2], NULL, 0); }

    printf("============================================================\n");
    printf(" Benchmark S0 / S1 / S2\n");
    printf("============================================================\n");
    printf(" scenarios : %llu\n", (unsigned long long)scenarios);
    printf(" graine    : 0x%08X\n", seed);
    printf(" ECU       : permissif (reset gate sur la session seule)\n");
    printf(" attaque   : session etendue -> reset, sans deverrouillage\n\n");

    bench_run(scenarios, seed, 500u, &r);

    printf("----------------------------------------------------------\n");
    printf(" %-42s %s\n", "", "resets NON autorises atteignant l'ECU");
    printf("----------------------------------------------------------\n");
    printf(" S0  ECU seul                              %20llu\n",
           (unsigned long long)r.s0_unauth);
    printf(" S1  filtre sans etat + ECU                %20llu\n",
           (unsigned long long)r.s1_unauth);
    printf(" S2  gateway AHDG + ECU                    %20llu\n",
           (unsigned long long)r.s2_unauth);
    printf("\n");
    printf(" disponibilite (flux legitimes servis)\n");
    printf("   S0  ECU seul               %llu / %llu\n",
           (unsigned long long)r.s0_avail, (unsigned long long)r.avail_total);
    printf("   S2  gateway AHDG + ECU      %llu / %llu\n",
           (unsigned long long)r.s2_avail, (unsigned long long)r.avail_total);
    printf("\n");
    printf(" latence d'admission gateway (S2)          %llu ns / requete\n",
           (unsigned long long)measure_admit_ns(seed));
    printf(" gateway : %u vues, %u transmises, %u refusees\n",
           r.gw_seen, r.gw_allowed, r.gw_dropped);
    printf("============================================================\n");

    if (r.s2_unauth != 0u)
    {
        printf("ECHEC : la gateway a laisse passer un reset non autorise.\n");
        return 1;
    }
    if (r.s1_unauth == 0u)
    {
        printf("ECHEC : le corpus ne demontre pas la difference.\n");
        return 1;
    }
    if (r.s2_avail != r.avail_total)
    {
        printf("ECHEC : la gateway a bloque un flux legitime.\n");
        return 1;
    }
    return 0;
}
