/*
 * ahdg_explore.c
 *
 * CLI de l'explorateur adversarial de l'espace d'etats UDS.
 *
 * Habillage mince : la logique d'attaque vit dans ahdg_explore_core.h,
 * partagee avec le module WebAssembly (web/wasm/ahdg_wasm.c) pour que la
 * ligne de commande et le simulateur en ligne ne puissent pas diverger.
 *
 * Voir docs/RESEARCH.md et docs/findings/AHDG-0001.md.
 *
 * Build :
 *   make explore
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "ahdg_explore_core.h"

static void explain(int inv, const ahdg_action_t *seq, int len)
{
    const hdg_invariant_info_t *info =
        hdg_invariant_info((hdg_invariant_id_t)inv);
    int i;

    printf("\n============================================================\n");
    printf(" CONTRE-EXEMPLE  —  invariant %s viole\n",
           (info != NULL) ? info->code : "?");
    printf("============================================================\n");
    if (info != NULL) { printf(" Propriete : %s\n", info->summary); }
    printf(" Sequence minimale : %d action(s)\n", len);
    for (i = 0; i < len; i++)
    {
        printf("   %2d. %s\n", i + 1, ahdg_action_name(seq[i]));
    }
    printf(" Decision AHDG : DROP + RECOVER (moteur M52+)\n");
    printf("============================================================\n");
}

int main(int argc, char **argv)
{
    uint64_t budget = 500000u;
    uint32_t seed = 0xA11CE;
    ahdg_results_t res;
    int total = 0;
    int i;

    if (argc > 1) { budget = strtoull(argv[1], NULL, 10); }
    if (argc > 2) { seed = (uint32_t)strtoul(argv[2], NULL, 0); }

    printf("============================================================\n");
    printf(" AHDG — exploration adversariale de l'espace d'etats UDS\n");
    printf("============================================================\n");
    printf(" cible      : src/uds/uds.c (code de production)\n");
    printf(" sequences  : %llu\n", (unsigned long long)budget);
    printf(" graine     : 0x%08X\n\n", seed);

    ahdg_run(budget, seed, 14, &res);

    for (i = 0; i < AHDG_EVALUATED_COUNT; i++)
    {
        int id = AHDG_EVALUATED[i];
        if (res.found[id] != 0)
        {
            explain(id, res.cex[id], res.cex_len[id]);
        }
    }

    printf("\n============================================================\n");
    printf(" Bilan\n");
    printf("============================================================\n");
    printf(" sequences jouees    : %llu\n", (unsigned long long)res.tested);
    printf(" etats de securite   : %d distincts\n\n", res.states);
    for (i = 0; i < AHDG_EVALUATED_COUNT; i++)
    {
        int id = AHDG_EVALUATED[i];
        const hdg_invariant_info_t *info =
            hdg_invariant_info((hdg_invariant_id_t)id);
        int hit = res.found[id];
        printf("   %-8s %s\n", (info != NULL) ? info->code : "?",
               hit ? "CONTRE-EXEMPLE TROUVE"
                   : "aucun contre-exemple (assurance bornee)");
        if (hit != 0) { total++; }
    }
    printf("\n Contre-exemples : %d\n", total);
    printf("============================================================\n");

    return (total == 0) ? 0 : 2;
}
