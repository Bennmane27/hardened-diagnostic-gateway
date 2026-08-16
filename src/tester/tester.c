/*
 * tester.c
 *
 * Client de diagnostic.
 *
 * Deroule un scenario de requetes UDS et decode les reponses, positives
 * comme negatives. Le transport et le reassemblage ISO-TP sont dans
 * diag_link.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "can_socket.h"
#include "diag_link.h"
#include "isotp.h"
#include "uds.h"
#include "ecu_data.h"

#define CAN_ID_TESTER_TO_ECU   0x7E0u
#define CAN_ID_ECU_TO_TESTER   0x7E8u

#define CAN_INTERFACE          "vcan0"
#define RX_TICK_MS             50u

/* Delai d'attente d'une reponse complete. */
#define RESPONSE_TIMEOUT_MS    2000u

static can_socket_t g_sock;
static diag_link_t  g_link;

static int g_steps = 0;
static int g_answered = 0;

/* ------------------------------------------------------------------ */
/* Decodage des reponses                                               */
/* ------------------------------------------------------------------ */

static void print_ascii_if_printable(const uint8_t *data, uint16_t len)
{
    uint16_t i;

    for (i = 0u; i < len; i++)
    {
        if ((data[i] < 0x20u) || (data[i] > 0x7Eu))
        {
            return;
        }
    }

    printf("  \"");
    for (i = 0u; i < len; i++)
    {
        printf("%c", (char)data[i]);
    }
    printf("\"");
}

static void print_uds_response(const uint8_t *payload, uint16_t len)
{
    if (len == 0u)
    {
        printf("  -> reponse vide\n");
        return;
    }

    /*
     * Une reponse negative commence par 0x7F. Ce test vient en premier :
     * 0x7F n'est pas un service mais un marqueur de rejet, et le
     * confondre ferait passer un refus pour une reponse incomprise.
     */
    if ((len == UDS_NEGATIVE_RESPONSE_LEN) &&
        (payload[0] == UDS_NEGATIVE_RESPONSE_SID))
    {
        printf("  -> REFUS  service 0x%02X, NRC 0x%02X (%s)\n",
               payload[1], payload[2], uds_nrc_to_string(payload[2]));
        return;
    }

    /* 0x50 : DiagnosticSessionControl. */
    if ((len >= 2u) &&
        (payload[0] == (UDS_SID_DIAGNOSTIC_SESSION_CONTROL +
                        UDS_POSITIVE_RESPONSE_OFFSET)))
    {
        printf("  -> OK     session active : %s\n",
               uds_session_to_string((uds_session_t)payload[1]));

        if (len >= 6u)
        {
            uint16_t p2      = (uint16_t)(((uint16_t)payload[2] << 8) |
                                          payload[3]);
            uint16_t p2_star = (uint16_t)(((uint16_t)payload[4] << 8) |
                                          payload[5]);
            printf("            P2Server_max %u ms, P2*Server_max %u ms\n",
                   p2, (unsigned)(p2_star * 10u));
        }
        return;
    }

    /* 0x62 : ReadDataByIdentifier. */
    if ((len >= 3u) &&
        (payload[0] == (UDS_SID_READ_DATA_BY_IDENTIFIER +
                        UDS_POSITIVE_RESPONSE_OFFSET)))
    {
        uint16_t did = (uint16_t)(((uint16_t)payload[1] << 8) | payload[2]);
        uint16_t data_len = (uint16_t)(len - 3u);
        uint16_t i;

        printf("  -> OK     DID 0x%04X (%s) = ",
               did, ecu_data_did_to_string(did));

        for (i = 0u; i < data_len; i++)
        {
            printf("%02X ", payload[3 + i]);
        }

        if ((did == DID_ENGINE_RPM) && (data_len == 2u))
        {
            printf(" = %u tr/min",
                   (unsigned)(((uint16_t)payload[3] << 8) | payload[4]));
        }
        else if ((did == DID_VEHICLE_SPEED) && (data_len == 1u))
        {
            printf(" = %u km/h", payload[3]);
        }
        else if ((did == DID_COOLANT_TEMPERATURE) && (data_len == 2u))
        {
            printf(" = %d C",
                   (int)(int16_t)(((uint16_t)payload[3] << 8) | payload[4]));
        }
        else if ((did == DID_BATTERY_VOLTAGE) && (data_len == 2u))
        {
            unsigned mv = (unsigned)(((uint16_t)payload[3] << 8) | payload[4]);
            printf(" = %u.%03u V", mv / 1000u, mv % 1000u);
        }
        else
        {
            print_ascii_if_printable(&payload[3], data_len);
        }

        printf("\n");
        return;
    }

    printf("  -> reponse non interpretee (%u octets)\n", len);
}

/* ------------------------------------------------------------------ */
/* Echange                                                             */
/* ------------------------------------------------------------------ */

static void request(const char *label,
                    const uint8_t *payload,
                    uint16_t payload_len)
{
    const uint8_t *response = NULL;
    uint16_t response_len = 0u;
    int r;

    g_steps++;
    printf("\n[%d] %s\n", g_steps, label);

    if (diag_link_send(&g_link, payload, payload_len) != 0)
    {
        printf("  -> ECHEC emission (%s)\n",
               isotp_result_to_string(g_link.last_error));
        return;
    }

    r = diag_link_recv(&g_link, &response, &response_len,
                       RESPONSE_TIMEOUT_MS);

    if (r < 0)
    {
        printf("  -> ERREUR de reception\n");
        return;
    }

    if (r == 0)
    {
        printf("  -> AUCUNE REPONSE (delai de %u ms expire)\n",
               RESPONSE_TIMEOUT_MS);
        return;
    }

    g_answered++;
    print_uds_response(response, response_len);
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    int verbose = 1;

    if ((argc > 1) && (argv[1][0] == '-') && (argv[1][1] == 'q'))
    {
        verbose = 0;
    }

    if (can_socket_open(&g_sock, CAN_INTERFACE, RX_TICK_MS) != 0)
    {
        return 1;
    }

    diag_link_init(&g_link, &g_sock,
                   CAN_ID_TESTER_TO_ECU,   /* on emet sur 7E0 */
                   CAN_ID_ECU_TO_TESTER,   /* on ecoute 7E8   */
                   verbose);

    printf("=== Tester de diagnostic ===\n");
    printf("Interface : %s\n", CAN_INTERFACE);

    {
        const uint8_t req[] = { UDS_SID_DIAGNOSTIC_SESSION_CONTROL, 0x03 };
        request("DiagnosticSessionControl -> Extended", req, sizeof(req));
    }
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0xF1, 0x89 };
        request("ReadDataByIdentifier -> version logicielle",
                req, sizeof(req));
    }
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0x01, 0x00 };
        request("ReadDataByIdentifier -> regime moteur", req, sizeof(req));
    }
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0x01, 0x02 };
        request("ReadDataByIdentifier -> temperature moteur",
                req, sizeof(req));
    }
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0x01, 0x03 };
        request("ReadDataByIdentifier -> tension batterie", req, sizeof(req));
    }

    /*
     * Le VIN fait 17 octets : la reponse depasse ce qu'une Single Frame
     * peut porter. C'est le transfert multi-trames qui la rend possible.
     */
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0xF1, 0x90 };
        request("ReadDataByIdentifier -> VIN (multi-trames)",
                req, sizeof(req));
    }

    /* --- Chemins de refus --- */
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0xAB, 0xCD };
        request("ReadDataByIdentifier -> identifiant inconnu",
                req, sizeof(req));
    }
    {
        const uint8_t req[] = { 0x99, 0x00 };
        request("Service inexistant 0x99", req, sizeof(req));
    }

    printf("\n=== %d etapes, %d reponses recues ===\n", g_steps, g_answered);

    can_socket_close(&g_sock);
    return 0;
}
