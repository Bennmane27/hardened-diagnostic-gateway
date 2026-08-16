/*
 * gateway_main.c
 *
 * Passerelle de diagnostic AHDG, en ligne, entre DEUX bus CAN.
 *
 *     Testeur/Attaquant ── bus externe ──► [ GATEWAY ] ──► bus de confiance ── ECU
 *
 * La passerelle reconstruit chaque message de diagnostic (reassemblage
 * ISO-TP), demande a la politique durcie (gw_admit) si la requete a le
 * droit d'atteindre l'ECU, et :
 *
 *   - ALLOW  : elle transmet la requete a l'ECU, attend sa reponse, la
 *              renvoie au testeur, et se synchronise dessus.
 *   - DROP   : l'ECU ne voit RIEN. La passerelle renvoie elle-meme au
 *              testeur la reponse negative de la politique (recovery :
 *              le testeur n'est jamais laisse sans reponse).
 *
 * C'est l'application concrete du modele : enforcement AVANT l'ECU. La
 * logique de decision (gateway.c) est portable ; seul ce fichier, comme
 * ecu.c et tester.c, connait SocketCAN.
 *
 * Interfaces (defaut vcan0 externe, vcan1 confiance) :
 *   HDG_IFACE_EXT=vcan0 HDG_IFACE_ECU=vcan1 ./build/gateway
 *
 * Usage : ./build/gateway [-q]
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>

#include "can_socket.h"
#include "diag_link.h"
#include "uds.h"
#include "gateway.h"

#define CAN_ID_TESTER_TO_ECU   0x7E0u
#define CAN_ID_ECU_TO_TESTER   0x7E8u
#define RX_TICK_MS             50u
#define ECU_TIMEOUT_MS         1000u

static can_socket_t g_sock_ext;   /* face au testeur (bus externe)     */
static can_socket_t g_sock_ecu;   /* face a l'ECU (bus de confiance)   */
static diag_link_t  g_link_ext;
static diag_link_t  g_link_ecu;
static gw_t         g_gw;

static volatile sig_atomic_t g_running = 1;
static void on_signal(int s) { (void)s; g_running = 0; }

int main(int argc, char **argv)
{
    const char *iface_ext = getenv("HDG_IFACE_EXT");
    const char *iface_ecu = getenv("HDG_IFACE_ECU");
    int verbose = 1;
    uint64_t forwarded = 0u, blocked = 0u;

    if (iface_ext == NULL) { iface_ext = "vcan0"; }
    if (iface_ecu == NULL) { iface_ecu = "vcan1"; }
    if ((argc > 1) && (argv[1][0] == '-') && (argv[1][1] == 'q')) { verbose = 0; }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (can_socket_open(&g_sock_ext, iface_ext, RX_TICK_MS) != 0) { return 1; }
    if (can_socket_open(&g_sock_ecu, iface_ecu, RX_TICK_MS) != 0)
    {
        can_socket_close(&g_sock_ext);
        return 1;
    }

    /* Cote testeur : on se comporte comme l'ECU (ecoute 7E0, repond 7E8). */
    diag_link_init(&g_link_ext, &g_sock_ext,
                   CAN_ID_ECU_TO_TESTER, CAN_ID_TESTER_TO_ECU, 0);
    /* Cote ECU : on se comporte comme un testeur (emet 7E0, ecoute 7E8). */
    diag_link_init(&g_link_ecu, &g_sock_ecu,
                   CAN_ID_TESTER_TO_ECU, CAN_ID_ECU_TO_TESTER, 0);

    gw_init(&g_gw);

    printf("=== Passerelle AHDG ===\n");
    printf("Bus externe (testeur)   : %s\n", iface_ext);
    printf("Bus de confiance (ECU)  : %s\n", iface_ecu);
    printf("Politique : le serveur UDS durci comme controleur d'admission\n");
    printf("En attente...\n");

    while (g_running != 0)
    {
        const uint8_t *request = NULL;
        uint16_t request_len = 0u;
        int r = diag_link_poll(&g_link_ext, &request, &request_len);

        if (r < 0) { break; }
        if (r == 0) { continue; }

        {
            uint8_t gw_resp[UDS_MAX_RESPONSE_SIZE];
            uint16_t gw_resp_len = 0u;
            uint32_t now = can_monotonic_ms();
            gw_verdict_t v = gw_admit_ex(&g_gw, request, request_len, now,
                                         gw_resp, (uint16_t)sizeof(gw_resp),
                                         &gw_resp_len);

            if (v == GW_ALLOW)
            {
                const uint8_t *ecu_resp = NULL;
                uint16_t ecu_resp_len = 0u;

                if (diag_link_send(&g_link_ecu, request, request_len) != 0)
                {
                    continue;
                }
                forwarded++;

                if (diag_link_recv(&g_link_ecu, &ecu_resp, &ecu_resp_len,
                                   ECU_TIMEOUT_MS) == 1)
                {
                    gw_observe_response(&g_gw, ecu_resp, ecu_resp_len);
                    (void)diag_link_send(&g_link_ext, ecu_resp, ecu_resp_len);
                }
                if (verbose != 0)
                {
                    printf("  ALLOW  service 0x%02X  -> ECU\n", request[0]);
                }
            }
            else /* GW_DROP */
            {
                blocked++;
                /* Recovery : le testeur recoit la reponse de refus, l'ECU rien. */
                if (gw_resp_len > 0u)
                {
                    (void)diag_link_send(&g_link_ext, gw_resp, gw_resp_len);
                }
                printf("  DROP   service 0x%02X  NRC 0x%02X (%s)  "
                       "-- l'ECU n'a rien vu\n",
                       request[0], g_gw.last_nrc, gw_last_reason(&g_gw));
            }
        }
    }

    printf("\n--- Statistiques passerelle ---\n");
    printf("  requetes vues     : %u\n", g_gw.stat_seen);
    printf("  transmises a l'ECU: %llu\n", (unsigned long long)forwarded);
    printf("  bloquees          : %llu\n", (unsigned long long)blocked);

    can_socket_close(&g_sock_ext);
    can_socket_close(&g_sock_ecu);
    return 0;
}
