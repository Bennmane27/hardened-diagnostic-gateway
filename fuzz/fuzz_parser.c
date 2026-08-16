/*
 * fuzz_parser.c
 *
 * Fuzzing des analyseurs, hors reseau.
 *
 * Deux modes de fuzzing coexistent dans ce projet et repondent a des
 * questions differentes :
 *
 *   - fuzzing d'analyseur (ce fichier) : on alimente directement les
 *     machines a etats ISO-TP et UDS en memoire. Des millions de cas
 *     par seconde, reproductibles, et sous sanitizers. C'est ce qui
 *     trouve les debordements et les etats impossibles.
 *
 *   - fuzzing reseau (tools/fuzzer) : on injecte de vraies trames sur
 *     le bus. Beaucoup plus lent, mais c'est le seul qui teste la
 *     chaine complete, sockets et boucle de service comprises.
 *
 * Le generateur est un congruentiel lineaire a graine explicite : la
 * meme graine rejoue exactement la meme campagne. Un cas qui echoue est
 * donc reproductible, ce qu'un rand() non ensemence ne permettrait pas.
 *
 * Build :
 *   make fuzz
 *
 * Usage :
 *   ./build/fuzz_parser [iterations] [graine]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "isotp.h"
#include "uds.h"

/* ------------------------------------------------------------------ */
/* Generateur reproductible                                            */
/* ------------------------------------------------------------------ */

static uint32_t g_rng;

static void rng_seed(uint32_t seed)
{
    g_rng = (seed != 0u) ? seed : 1u;
}

static uint32_t rng_next(void)
{
    /* xorshift32 : rapide, suffisant pour du fuzzing, non cryptographique. */
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}

static uint8_t rng_byte(void)
{
    return (uint8_t)(rng_next() & 0xFFu);
}

/* ------------------------------------------------------------------ */
/* Statistiques                                                        */
/* ------------------------------------------------------------------ */

typedef struct
{
    uint64_t cases;
    uint64_t isotp_frames;
    uint64_t uds_requests;
    uint64_t messages_assembled;
    uint64_t sequence_errors;
    uint64_t overflows;
    uint64_t timeouts;
    uint64_t negative_responses;
    uint64_t positive_responses;
    uint64_t anomalies;
} fuzz_stats_t;

static fuzz_stats_t g_stats;

static void anomaly(const char *what, uint32_t seed_at_case)
{
    g_stats.anomalies++;
    printf("ANOMALIE : %s (etat du generateur : %08X)\n", what, seed_at_case);
}

/* ------------------------------------------------------------------ */
/* Cible : machine a etats de reception ISO-TP                         */
/* ------------------------------------------------------------------ */

static isotp_rx_context_t g_rx;

/*
 * Genere une rafale de trames dans un transfert plausible mais
 * volontairement corrompu. Le fuzzing purement aleatoire est rejete
 * des le premier octet dans 15 cas sur 16 ; en partant d'une structure
 * valide et en la degradant, on atteint reellement le coeur du
 * reassemblage.
 */
static void fuzz_isotp_burst(uint32_t now_ms)
{
    isotp_rx_result_t out;
    uint8_t frame[ISOTP_CAN_FRAME_SIZE];
    int burst;
    int i;
    uint32_t state_before = g_rng;

    burst = (int)(rng_next() % 12u) + 1;

    for (i = 0; i < burst; i++)
    {
        uint8_t len;
        uint8_t k;
        uint32_t choice = rng_next() % 100u;

        for (k = 0u; k < ISOTP_CAN_FRAME_SIZE; k++)
        {
            frame[k] = rng_byte();
        }

        if (choice < 25u)
        {
            /* First Frame de longueur arbitraire. */
            frame[0] = (uint8_t)(0x10u | (rng_byte() & 0x0Fu));
        }
        else if (choice < 70u)
        {
            /*
             * Consecutive Frame. Une fois sur trois le numero de
             * sequence est correct, sinon il est faux : c'est le
             * scenario 21 22 27 au lieu de 21 22 23.
             */
            if ((rng_next() % 3u) == 0u)
            {
                frame[0] = (uint8_t)(0x20u | g_rx.next_sequence_number);
            }
            else
            {
                frame[0] = (uint8_t)(0x20u | (rng_byte() & 0x0Fu));
            }
        }
        else if (choice < 85u)
        {
            frame[0] = (uint8_t)(rng_byte() & 0x07u);   /* Single Frame */
        }
        else if (choice < 95u)
        {
            frame[0] = (uint8_t)(0x30u | (rng_byte() & 0x0Fu)); /* FC */
        }
        /* sinon : premier octet totalement aleatoire */

        /* DLC variable, y compris des trames plus courtes qu'annonce. */
        len = (uint8_t)(rng_next() % (ISOTP_CAN_FRAME_SIZE + 1u));

        if (isotp_rx_process(&g_rx, frame, len, now_ms, &out) != ISOTP_OK)
        {
            anomaly("isotp_rx_process a renvoye une erreur", state_before);
        }

        g_stats.isotp_frames++;

        /* --- Invariants verifies a chaque trame --- */

        if ((g_rx.state != ISOTP_RX_IDLE) &&
            (g_rx.state != ISOTP_RX_WAIT_CONSECUTIVE))
        {
            anomaly("etat de reception inconnu", state_before);
            isotp_rx_reset(&g_rx);
        }

        if (g_rx.received_length > g_rx.expected_length)
        {
            anomaly("plus d'octets recus qu'annonces", state_before);
            isotp_rx_reset(&g_rx);
        }

        if (g_rx.expected_length > ISOTP_MAX_PAYLOAD_SIZE)
        {
            anomaly("longueur annoncee au-dela du tampon", state_before);
            isotp_rx_reset(&g_rx);
        }

        switch (out.event)
        {
        case ISOTP_RX_EVENT_MESSAGE_READY:
            g_stats.messages_assembled++;
            if (out.message == NULL)
            {
                anomaly("message pret mais pointeur nul", state_before);
            }
            if (out.message_len > ISOTP_MAX_PAYLOAD_SIZE)
            {
                anomaly("message plus grand que le tampon", state_before);
            }
            break;

        case ISOTP_RX_EVENT_SEND_FLOW_CONTROL:
            if (out.fc_len != ISOTP_CAN_FRAME_SIZE)
            {
                anomaly("Flow Control de taille incorrecte", state_before);
            }
            if (out.reason == ISOTP_ERR_OVERFLOW)
            {
                g_stats.overflows++;
            }
            break;

        case ISOTP_RX_EVENT_ABORTED:
            if (out.reason == ISOTP_ERR_SEQUENCE_NUMBER)
            {
                g_stats.sequence_errors++;
            }
            if (g_rx.state != ISOTP_RX_IDLE)
            {
                anomaly("abandon sans retour au repos", state_before);
            }
            break;

        default:
            break;
        }
    }

    /*
     * Une trame manquante suivie du silence : le transfert doit finir
     * par expirer plutot que de rester ouvert indefiniment.
     */
    if ((rng_next() % 4u) == 0u)
    {
        (void)isotp_rx_poll_timeout(&g_rx, now_ms + ISOTP_N_CR_TIMEOUT_MS,
                                    &out);
        if (out.event == ISOTP_RX_EVENT_ABORTED)
        {
            g_stats.timeouts++;
            if (g_rx.state != ISOTP_RX_IDLE)
            {
                anomaly("timeout sans retour au repos", state_before);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Cible : serveur UDS                                                 */
/* ------------------------------------------------------------------ */

static uds_context_t g_uds;

static uds_result_t fuzz_did_read(uint16_t did, uint8_t *out,
                                  uint16_t out_capacity, uint16_t *out_len,
                                  void *user_ctx)
{
    uint16_t want;
    uint16_t i;

    (void)user_ctx;

    if ((did & 0x0Fu) == 0x0Fu)
    {
        return UDS_ERR_DID_NOT_FOUND;
    }

    /* Longueur derivee du DID, parfois plus grande que la capacite. */
    want = (uint16_t)((did % 600u) + 1u);

    if (want > out_capacity)
    {
        return UDS_ERR_BUFFER_TOO_SMALL;
    }

    for (i = 0u; i < want; i++)
    {
        out[i] = (uint8_t)(i ^ did);
    }
    *out_len = want;
    return UDS_OK;
}

static uds_result_t fuzz_dtc_read(uint8_t status_mask, uint8_t *out,
                                  uint16_t out_capacity, uint16_t *out_len,
                                  void *user_ctx)
{
    uint16_t count;
    uint16_t i;

    (void)user_ctx;

    count = (uint16_t)(status_mask % 40u);

    if ((uint32_t)(count * 4u) > (uint32_t)out_capacity)
    {
        return UDS_ERR_BUFFER_TOO_SMALL;
    }

    for (i = 0u; i < (uint16_t)(count * 4u); i++)
    {
        out[i] = (uint8_t)i;
    }
    *out_len = (uint16_t)(count * 4u);
    return UDS_OK;
}

static uds_result_t fuzz_dtc_clear(uint32_t group, void *user_ctx)
{
    (void)user_ctx;
    return (group == 0xFFFFFFu) ? UDS_OK : UDS_ERR_DID_NOT_FOUND;
}

static uds_result_t fuzz_reset(uint8_t type, void *user_ctx)
{
    (void)type;
    (void)user_ctx;
    return UDS_OK;
}

static void fuzz_uds_request(uint32_t now_ms)
{
    static const uint8_t INTERESTING_SIDS[] = {
        0x10u, 0x11u, 0x14u, 0x19u, 0x22u, 0x27u, 0x3Eu
    };

    uint8_t request[32];
    uint8_t response[UDS_MAX_RESPONSE_SIZE];
    uint16_t response_len = 0xFFFFu;
    uint16_t request_len;
    uds_result_t res;
    uint8_t i;
    uint32_t state_before = g_rng;

    request_len = (uint16_t)(rng_next() % (sizeof(request) + 1u));

    for (i = 0u; i < sizeof(request); i++)
    {
        request[i] = rng_byte();
    }

    /*
     * Trois quarts des requetes portent un SID reellement implemente.
     * Sans ce biais, presque tout serait rejete par serviceNotSupported
     * et les handlers ne seraient jamais atteints.
     */
    if ((request_len > 0u) && ((rng_next() % 4u) != 0u))
    {
        request[0] = INTERESTING_SIDS[rng_next() %
                                      (sizeof(INTERESTING_SIDS) /
                                       sizeof(INTERESTING_SIDS[0]))];
    }

    res = uds_handle_request(&g_uds, request, request_len, now_ms,
                             response, (uint16_t)sizeof(response),
                             &response_len);

    g_stats.uds_requests++;

    /* --- Invariants --- */

    if ((res != UDS_OK) && (res != UDS_NO_RESPONSE))
    {
        anomaly("uds_handle_request a renvoye une erreur interne",
                state_before);
    }

    if (res == UDS_OK)
    {
        if (response_len > sizeof(response))
        {
            anomaly("reponse plus grande que le tampon", state_before);
        }
        else if (response_len == 0u)
        {
            anomaly("reponse annoncee mais vide", state_before);
        }
        else if (response[0] == UDS_NEGATIVE_RESPONSE_SID)
        {
            g_stats.negative_responses++;
            if (response_len != UDS_NEGATIVE_RESPONSE_LEN)
            {
                anomaly("reponse negative de taille incorrecte",
                        state_before);
            }
        }
        else
        {
            g_stats.positive_responses++;

            /*
             * Toute reponse positive doit correspondre au SID demande
             * augmente de 0x40. Une reponse positive a un service que
             * l'on n'a pas demande serait une confusion d'etat.
             */
            if ((request_len > 0u) &&
                (response[0] != (uint8_t)(request[0] +
                                          UDS_POSITIVE_RESPONSE_OFFSET)))
            {
                anomaly("reponse positive sans rapport avec la requete",
                        state_before);
            }
        }
    }

    /*
     * Invariant de securite central : sans deverrouillage, ECUReset ne
     * doit JAMAIS obtenir de reponse positive, quelle que soit la suite
     * de requetes qui a precede.
     */
    if ((request_len >= 1u) && (request[0] == UDS_SID_ECU_RESET) &&
        (res == UDS_OK) && (response[0] == 0x51u) &&
        (g_uds.security_level == UDS_SECURITY_LOCKED))
    {
        anomaly("ECUReset accepte alors que la securite est verrouillee",
                state_before);
    }

    /* La session ne doit jamais prendre une valeur inconnue. */
    if ((g_uds.session != UDS_SESSION_DEFAULT) &&
        (g_uds.session != UDS_SESSION_EXTENDED) &&
        (g_uds.session != UDS_SESSION_PROGRAMMING))
    {
        anomaly("session dans un etat inconnu", state_before);
    }
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    uint64_t iterations = 200000u;
    uint32_t seed = 0xC0FFEEu;
    uint64_t n;
    uint32_t now_ms = 0u;

    if (argc > 1)
    {
        iterations = strtoull(argv[1], NULL, 10);
    }
    if (argc > 2)
    {
        seed = (uint32_t)strtoul(argv[2], NULL, 0);
    }

    rng_seed(seed);
    memset(&g_stats, 0, sizeof(g_stats));

    isotp_rx_init(&g_rx);
    uds_init(&g_uds);
    uds_set_did_provider(&g_uds, fuzz_did_read, NULL);
    uds_set_dtc_provider(&g_uds, fuzz_dtc_read, fuzz_dtc_clear);
    uds_set_reset_handler(&g_uds, fuzz_reset);

    printf("=============================================\n");
    printf(" Fuzzing des analyseurs\n");
    printf("=============================================\n");
    printf(" iterations : %llu\n", (unsigned long long)iterations);
    printf(" graine     : 0x%08X\n", seed);
    printf("\n");

    for (n = 0u; n < iterations; n++)
    {
        now_ms += (rng_next() % 40u);

        fuzz_isotp_burst(now_ms);
        fuzz_uds_request(now_ms);

        /*
         * Le contexte n'est volontairement PAS reinitialise a chaque
         * tour : les etats interessants sont ceux que l'on atteint
         * apres une longue suite de requetes mal formees.
         */
        if ((rng_next() % 5000u) == 0u)
        {
            isotp_rx_init(&g_rx);
            uds_init(&g_uds);
            uds_set_did_provider(&g_uds, fuzz_did_read, NULL);
            uds_set_dtc_provider(&g_uds, fuzz_dtc_read, fuzz_dtc_clear);
            uds_set_reset_handler(&g_uds, fuzz_reset);
        }

        g_stats.cases++;
    }

    printf("--- Resultats ---\n");
    printf("  cas joues              : %llu\n",
           (unsigned long long)g_stats.cases);
    printf("  trames ISO-TP          : %llu\n",
           (unsigned long long)g_stats.isotp_frames);
    printf("  messages reassembles   : %llu\n",
           (unsigned long long)g_stats.messages_assembled);
    printf("  erreurs de sequence    : %llu\n",
           (unsigned long long)g_stats.sequence_errors);
    printf("  debordements refuses   : %llu\n",
           (unsigned long long)g_stats.overflows);
    printf("  delais expires         : %llu\n",
           (unsigned long long)g_stats.timeouts);
    printf("  requetes UDS           : %llu\n",
           (unsigned long long)g_stats.uds_requests);
    printf("  reponses positives     : %llu\n",
           (unsigned long long)g_stats.positive_responses);
    printf("  reponses negatives     : %llu\n",
           (unsigned long long)g_stats.negative_responses);
    printf("\n");
    printf("  ANOMALIES              : %llu\n",
           (unsigned long long)g_stats.anomalies);
    printf("=============================================\n");

    return (g_stats.anomalies == 0u) ? 0 : 1;
}
