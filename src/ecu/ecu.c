/*
 * ecu.c
 *
 * ECU virtuel.
 *
 * Boucle de service : recevoir un message de diagnostic, le confier au
 * serveur UDS, renvoyer la reponse. Tout le detail du transport et du
 * reassemblage ISO-TP est dans diag_link.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>

#include "can_socket.h"
#include "diag_link.h"
#include "isotp.h"
#include "uds.h"
#include "ecu_data.h"

#define CAN_ID_TESTER_TO_ECU   0x7E0u
#define CAN_ID_ECU_TO_TESTER   0x7E8u

#define CAN_INTERFACE          "vcan0"

/*
 * Delai de reception du socket. Court volontairement : c'est ce
 * reveil regulier qui permet de verifier l'expiration des
 * temporisations ISO-TP meme quand le bus est silencieux.
 */
#define RX_TICK_MS             50u

/* Contextes statiques : ni malloc, ni variable automatique volumineuse. */
static can_socket_t g_sock;
static diag_link_t  g_link;
static uds_context_t g_uds;
static ecu_data_t    g_data;

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static void print_statistics(void)
{
    printf("\n--- Statistiques ISO-TP ---\n");
    printf("  trames recues        : %u\n", g_link.rx.stat_frames);
    printf("  messages reassembles : %u\n", g_link.rx.stat_messages);
    printf("  trames rejetees      : %u\n", g_link.rx.stat_rejected);
    printf("  erreurs de sequence  : %u\n", g_link.rx.stat_sequence_errors);
    printf("  debordements         : %u\n", g_link.rx.stat_overflows);
    printf("  delais expires       : %u\n", g_link.rx.stat_timeouts);
    printf("  messages emis        : %u\n", g_link.tx.stat_messages);
    printf("  trames emises        : %u\n", g_link.tx.stat_frames);
}

int main(int argc, char **argv)
{
    const char *iface = getenv("HDG_IFACE");
    if (iface == NULL) { iface = CAN_INTERFACE; }

    int verbose = 1;

    if ((argc > 1) && (argv[1][0] == '-') && (argv[1][1] == 'q'))
    {
        verbose = 0;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (can_socket_open(&g_sock, iface, RX_TICK_MS) != 0)
    {
        return 1;
    }

    diag_link_init(&g_link, &g_sock,
                   CAN_ID_ECU_TO_TESTER,   /* on emet sur 7E8  */
                   CAN_ID_TESTER_TO_ECU,   /* on ecoute 7E0    */
                   verbose);

    ecu_data_init(&g_data);
    uds_init(&g_uds);
    uds_set_did_provider(&g_uds, ecu_data_read_did, &g_data);
    uds_set_dtc_provider(&g_uds, ecu_data_read_dtc, ecu_data_clear_dtc);
    uds_set_reset_handler(&g_uds, ecu_data_reset);

    /*
     * Le generateur de graines de SecurityAccess est deterministe.
     * Sans entropie, deux executions produiraient la meme suite. Ce
     * n'est pas cryptographique pour autant : voir docs/security.md.
     */
    uds_seed_entropy(&g_uds, can_monotonic_ms());

    printf("=== ECU virtuel ===\n");
    printf("Interface   : %s\n", iface);
    printf("Requetes    : 0x%03X\n", CAN_ID_TESTER_TO_ECU);
    printf("Reponses    : 0x%03X\n", CAN_ID_ECU_TO_TESTER);
    printf("Session     : %s\n", uds_session_to_string(g_uds.session));
    printf("En attente...\n");

    while (g_running != 0)
    {
        const uint8_t *request = NULL;
        uint16_t request_len = 0u;
        int r;

        r = diag_link_poll(&g_link, &request, &request_len);

        if (r < 0)
        {
            break;
        }
        if (r == 0)
        {
            /*
             * Bus silencieux : c'est le moment de laisser expirer ce
             * qui doit expirer, session etendue comprise.
             */
            uds_poll(&g_uds, can_monotonic_ms());
            continue;
        }

        /* Les grandeurs simulees avancent a chaque requete traitee. */
        ecu_data_tick(&g_data);

        printf("\n[requete %u octets] %s\n",
               request_len, uds_sid_to_string(request[0]));

        {
            uint8_t response[UDS_MAX_RESPONSE_SIZE];
            uint16_t response_len = 0u;
            uds_result_t uds_res;

            uds_res = uds_handle_request(&g_uds,
                                         request,
                                         request_len,
                                         can_monotonic_ms(),
                                         response,
                                         (uint16_t)sizeof(response),
                                         &response_len);

            if (uds_res == UDS_NO_RESPONSE)
            {
                printf("  UDS : aucune reponse a emettre\n");
                printf("  Session : %s\n",
                       uds_session_to_string(g_uds.session));
                continue;
            }

            if (uds_res != UDS_OK)
            {
                printf("  UDS : erreur interne (%s)\n",
                       uds_result_to_string(uds_res));
                continue;
            }

            if (response[0] == UDS_NEGATIVE_RESPONSE_SID)
            {
                printf("  UDS : REFUS service 0x%02X, NRC 0x%02X (%s)\n",
                       response[1], response[2],
                       uds_nrc_to_string(response[2]));
                printf("  Session : %s | Securite : %s\n",
                       uds_session_to_string(g_uds.session),
                       (g_uds.security_level == UDS_SECURITY_LOCKED)
                           ? "verrouillee" : "deverrouillee");
            }
            else
            {
                printf("  UDS : reponse positive 0x%02X, %u octets\n",
                       response[0], response_len);
                printf("  Session : %s | Securite : %s\n",
                       uds_session_to_string(g_uds.session),
                       (g_uds.security_level == UDS_SECURITY_LOCKED)
                           ? "verrouillee" : "deverrouillee");
            }

            if (diag_link_send(&g_link, response, response_len) != 0)
            {
                printf("  ISO-TP : emission echouee (%s)\n",
                       isotp_result_to_string(g_link.last_error));
            }
        }
    }

    print_statistics();
    can_socket_close(&g_sock);
    return 0;
}
