/*
 * fuzz_bus.c
 *
 * Injecteur de fautes sur le bus CAN.
 *
 * Contrairement au fuzzing d'analyseur, qui alimente les machines a
 * etats en memoire, celui-ci emet de VRAIES trames sur vcan0 et parle a
 * un ECU qui tourne dans un autre processus. Il est bien plus lent,
 * mais il est le seul a tester la chaine complete : socket, boucle de
 * service, reassemblage, serveur UDS.
 *
 * Le critere de reussite n'est pas "l'ECU a rejete la trame" mais
 * "l'ECU repond encore correctement a une requete valide APRES avoir
 * ete agresse". D'ou la sonde de vitalite periodique : c'est elle qui
 * distingue un rejet propre d'un contexte definitivement casse.
 *
 * Usage :
 *   ./build/fuzz_bus [cycles] [graine]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>

#include "can_socket.h"
#include "isotp.h"
#include "uds.h"

#define CAN_ID_TESTER_TO_ECU  0x7E0u
#define CAN_ID_ECU_TO_TESTER  0x7E8u
#define CAN_INTERFACE         "vcan0"
#define RX_TICK_MS            60u

/* Une sonde de vitalite toutes les N attaques. */
#define LIVENESS_EVERY        25u

static can_socket_t g_sock;
static volatile sig_atomic_t g_running = 1;

static uint32_t g_rng;

static void on_signal(int sig) { (void)sig; g_running = 0; }

static uint32_t rng_next(void)
{
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}

static uint8_t rng_byte(void) { return (uint8_t)(rng_next() & 0xFFu); }

/* ------------------------------------------------------------------ */
/* Statistiques                                                        */
/* ------------------------------------------------------------------ */

typedef struct
{
    uint64_t frames_sent;
    uint64_t attacks;
    uint64_t probes;
    uint64_t probes_answered;
    uint64_t probes_failed;
    uint64_t unexpected_positive;
} bus_stats_t;

static bus_stats_t g_stats;

/* ------------------------------------------------------------------ */
/* Emission                                                            */
/* ------------------------------------------------------------------ */

static void send_raw(const uint8_t *data, uint8_t len)
{
    (void)can_socket_send(&g_sock, CAN_ID_TESTER_TO_ECU, data, len);
    g_stats.frames_sent++;
}

/* Vide la file de reception sans rien interpreter. */
static void drain(void)
{
    uint32_t id;
    uint8_t data[8];
    uint8_t len;
    int guard;

    for (guard = 0; guard < 64; guard++)
    {
        if (can_socket_recv(&g_sock, &id, data, &len) != 1)
        {
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Scenarios cibles                                                    */
/*                                                                     */
/* Le fuzzing purement aleatoire ne trouve presque jamais les cas       */
/* interessants d'un protocole a etats : il faut construire des         */
/* sequences plausibles puis les degrader a un endroit precis.          */
/* ------------------------------------------------------------------ */

static void attack_bad_sequence_number(void)
{
    /* First Frame annoncant 20 octets, puis 21 22 27 au lieu de 21 22 23. */
    uint8_t ff[8] = { 0x10, 0x14, 0x62, 0xF1, 0x90, 0x01, 0x02, 0x03 };
    uint8_t cf[8];
    uint8_t sn[3] = { 0x21, 0x22, 0x27 };
    int i;

    send_raw(ff, 8u);

    for (i = 0; i < 3; i++)
    {
        memset(cf, (uint8_t)(0xA0 + i), sizeof(cf));
        cf[0] = sn[i];
        send_raw(cf, 8u);
    }
}

static void attack_missing_consecutive_frame(void)
{
    /* FF puis une seule CF, puis plus rien : N_Cr doit expirer. */
    uint8_t ff[8] = { 0x10, 0x20, 1, 2, 3, 4, 5, 6 };
    uint8_t cf[8] = { 0x21, 7, 8, 9, 10, 11, 12, 13 };

    send_raw(ff, 8u);
    send_raw(cf, 8u);
}

static void attack_oversized_announcement(void)
{
    /* Forme etendue annoncant 4 Go. Doit produire un FC Overflow. */
    uint8_t ff[8] = { 0x10, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xBB };
    send_raw(ff, 8u);
}

static void attack_truncated_single_frame(void)
{
    /* SF_DL = 7 mais DLC = 2 : la trame ment sur sa longueur. */
    uint8_t sf[2] = { 0x07, 0x10 };
    send_raw(sf, 2u);
}

static void attack_orphan_consecutive_frames(void)
{
    uint8_t cf[8];
    int i;

    for (i = 0; i < 5; i++)
    {
        memset(cf, (uint8_t)i, sizeof(cf));
        cf[0] = (uint8_t)(0x21 + i);
        send_raw(cf, 8u);
    }
}

static void attack_invalid_pci(void)
{
    uint8_t frame[8];
    uint8_t i;

    for (i = 0u; i < 8u; i++) { frame[i] = rng_byte(); }
    /* Types 4 a 15 : inexistants dans la norme. */
    frame[0] = (uint8_t)(((rng_next() % 12u) + 4u) << 4);
    send_raw(frame, (uint8_t)((rng_next() % 8u) + 1u));
}

static void attack_interleaved_transfers(void)
{
    /* Deux First Frame consecutives : la seconde doit ecraser la premiere. */
    uint8_t ff1[8] = { 0x10, 0x14, 1, 1, 1, 1, 1, 1 };
    uint8_t ff2[8] = { 0x10, 0x0C, 2, 2, 2, 2, 2, 2 };
    uint8_t cf[8]  = { 0x21, 3, 3, 3, 3, 3, 3, 3 };

    send_raw(ff1, 8u);
    send_raw(ff2, 8u);
    send_raw(cf, 8u);
}

static void attack_uds_malformed(void)
{
    static const uint8_t SIDS[] = { 0x10, 0x11, 0x14, 0x19, 0x22, 0x27, 0x3E };
    uint8_t frame[8];
    uint8_t payload_len;
    uint8_t i;

    payload_len = (uint8_t)((rng_next() % 7u) + 1u);

    frame[0] = payload_len;
    frame[1] = SIDS[rng_next() % (sizeof(SIDS) / sizeof(SIDS[0]))];

    for (i = 2u; i < 8u; i++) { frame[i] = rng_byte(); }

    send_raw(frame, 8u);
}

static void attack_security_without_seed(void)
{
    /* Une cle envoyee sans avoir demande de graine. */
    uint8_t frame[8] = { 0x06, 0x27, 0x02, 0xDE, 0xAD, 0xBE, 0xEF, 0x00 };
    send_raw(frame, 8u);
}

static void attack_reset_without_security(void)
{
    /* La commande sensible, sans aucun deverrouillage. */
    uint8_t frame[8] = { 0x02, 0x11, 0x01, 0, 0, 0, 0, 0 };
    send_raw(frame, 8u);
}

static void attack_flood(void)
{
    uint8_t frame[8];
    int i;

    for (i = 0; i < 40; i++)
    {
        uint8_t k;
        for (k = 0u; k < 8u; k++) { frame[k] = rng_byte(); }
        send_raw(frame, 8u);
    }
}

typedef struct
{
    const char *name;
    void (*run)(void);
} scenario_t;

static const scenario_t SCENARIOS[] = {
    { "numero de sequence incorrect",     attack_bad_sequence_number     },
    { "Consecutive Frame manquante",      attack_missing_consecutive_frame },
    { "longueur annoncee demesuree",      attack_oversized_announcement  },
    { "Single Frame tronquee",            attack_truncated_single_frame  },
    { "Consecutive Frames orphelines",    attack_orphan_consecutive_frames },
    { "type de trame inexistant",         attack_invalid_pci             },
    { "transferts entrelaces",            attack_interleaved_transfers   },
    { "requete UDS malformee",            attack_uds_malformed           },
    { "cle de securite sans graine",      attack_security_without_seed   },
    { "ECUReset sans deverrouillage",     attack_reset_without_security  },
    { "rafale de trames aleatoires",      attack_flood                   }
};

#define SCENARIO_COUNT (sizeof(SCENARIOS) / sizeof(SCENARIOS[0]))

static uint64_t g_scenario_counts[SCENARIO_COUNT];

/* ------------------------------------------------------------------ */
/* Sonde de vitalite                                                   */
/* ------------------------------------------------------------------ */

/*
 * Emet une requete parfaitement valide et verifie que l'ECU y repond
 * correctement. C'est le seul critere qui compte : rejeter une attaque
 * ne sert a rien si le contexte reste casse ensuite.
 *
 * Retour : 1 si l'ECU a repondu comme attendu.
 */
static int liveness_probe(void)
{
    uint8_t request[8] = { 0x03, 0x22, 0xF1, 0x89, 0, 0, 0, 0 };
    uint32_t id;
    uint8_t data[8];
    uint8_t len;
    int guard;

    drain();
    send_raw(request, 8u);
    g_stats.probes++;

    for (guard = 0; guard < 40; guard++)
    {
        if (can_socket_recv(&g_sock, &id, data, &len) != 1)
        {
            continue;
        }
        if (id != CAN_ID_ECU_TO_TESTER)
        {
            continue;
        }

        /* Attendu : 06 62 F1 89 01 04 02 */
        if ((len >= 5u) && (data[0] == 0x06u) && (data[1] == 0x62u) &&
            (data[2] == 0xF1u) && (data[3] == 0x89u))
        {
            g_stats.probes_answered++;
            return 1;
        }
    }

    g_stats.probes_failed++;
    return 0;
}

/*
 * Verifie qu'aucune attaque n'a obtenu une reponse positive a
 * ECUReset. C'est l'invariant de securite du scenario de demonstration.
 */
static void watch_for_unexpected_positive(void)
{
    uint32_t id;
    uint8_t data[8];
    uint8_t len;
    int guard;

    for (guard = 0; guard < 32; guard++)
    {
        if (can_socket_recv(&g_sock, &id, data, &len) != 1)
        {
            return;
        }
        if ((id == CAN_ID_ECU_TO_TESTER) && (len >= 2u) &&
            (data[1] == 0x51u))
        {
            g_stats.unexpected_positive++;
            printf("ALERTE : ECUReset accepte sans deverrouillage\n");
        }
    }
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    uint64_t cycles = 200u;
    uint64_t c;
    uint32_t seed = 0xBADC0DEu;

    if (argc > 1) { cycles = strtoull(argv[1], NULL, 10); }
    if (argc > 2) { seed = (uint32_t)strtoul(argv[2], NULL, 0); }

    g_rng = (seed != 0u) ? seed : 1u;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (can_socket_open(&g_sock, CAN_INTERFACE, RX_TICK_MS) != 0)
    {
        return 1;
    }

    memset(&g_stats, 0, sizeof(g_stats));
    memset(g_scenario_counts, 0, sizeof(g_scenario_counts));

    printf("=============================================\n");
    printf(" Injecteur de fautes CAN\n");
    printf("=============================================\n");
    printf(" interface : %s\n", CAN_INTERFACE);
    printf(" cycles    : %llu\n", (unsigned long long)cycles);
    printf(" graine    : 0x%08X\n", seed);
    printf(" scenarios : %u\n", (unsigned)SCENARIO_COUNT);
    printf("\n");

    /* L'ECU doit repondre AVANT toute attaque, sinon le test ne vaut rien. */
    if (liveness_probe() == 0)
    {
        printf("ECHEC : l'ECU ne repond pas avant meme la premiere attaque.\n");
        printf("        Lancez ./build/ecu dans un autre terminal.\n");
        can_socket_close(&g_sock);
        return 1;
    }
    printf("ECU present et fonctionnel. Debut de la campagne.\n\n");

    for (c = 0u; (c < cycles) && (g_running != 0); c++)
    {
        size_t index = (size_t)(rng_next() % SCENARIO_COUNT);

        SCENARIOS[index].run();
        g_scenario_counts[index]++;
        g_stats.attacks++;

        watch_for_unexpected_positive();

        if (((c + 1u) % LIVENESS_EVERY) == 0u)
        {
            if (liveness_probe() == 0)
            {
                printf("ECHEC : l'ECU ne repond plus apres %llu attaques.\n",
                       (unsigned long long)g_stats.attacks);
                break;
            }
            printf("  %6llu attaques ... ECU toujours operationnel\n",
                   (unsigned long long)g_stats.attacks);
        }
    }

    /* Sonde finale. */
    (void)liveness_probe();

    printf("\n--- Repartition des scenarios ---\n");
    {
        size_t i;
        for (i = 0u; i < SCENARIO_COUNT; i++)
        {
            printf("  %-34s %6llu\n", SCENARIOS[i].name,
                   (unsigned long long)g_scenario_counts[i]);
        }
    }

    printf("\n--- Resultats ---\n");
    printf("  attaques jouees        : %llu\n",
           (unsigned long long)g_stats.attacks);
    printf("  trames emises          : %llu\n",
           (unsigned long long)g_stats.frames_sent);
    printf("  sondes de vitalite     : %llu\n",
           (unsigned long long)g_stats.probes);
    printf("  sondes reussies        : %llu\n",
           (unsigned long long)g_stats.probes_answered);
    printf("  sondes echouees        : %llu\n",
           (unsigned long long)g_stats.probes_failed);
    printf("  ECUReset non autorises : %llu\n",
           (unsigned long long)g_stats.unexpected_positive);
    printf("=============================================\n");

    can_socket_close(&g_sock);

    return ((g_stats.probes_failed == 0u) &&
            (g_stats.unexpected_positive == 0u)) ? 0 : 1;
}
