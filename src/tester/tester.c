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

    /* 0x59 : ReadDTCInformation. */
    if ((len >= 3u) &&
        (payload[0] == (UDS_SID_READ_DTC_INFORMATION +
                        UDS_POSITIVE_RESPONSE_OFFSET)))
    {
        uint16_t count = (uint16_t)((len - 3u) / 4u);
        uint16_t i;

        printf("  -> OK     %u code(s) defaut\n", count);

        for (i = 0u; i < count; i++)
        {
            const uint8_t *rec = &payload[3u + (i * 4u)];
            uint32_t code = (((uint32_t)rec[0]) << 16) |
                            (((uint32_t)rec[1]) << 8) |
                            ((uint32_t)rec[2]);

            printf("            %06X  statut %02X  %s\n",
                   code, rec[3], ecu_data_dtc_to_string(code));
        }
        return;
    }

    /* 0x67 : SecurityAccess. */
    if ((len >= 2u) &&
        (payload[0] == (UDS_SID_SECURITY_ACCESS +
                        UDS_POSITIVE_RESPONSE_OFFSET)))
    {
        if ((payload[1] == UDS_SECURITY_REQUEST_SEED) && (len >= 6u))
        {
            uint32_t seed = (((uint32_t)payload[2]) << 24) |
                            (((uint32_t)payload[3]) << 16) |
                            (((uint32_t)payload[4]) << 8) |
                            ((uint32_t)payload[5]);
            printf("  -> OK     graine recue : %08X\n", seed);
        }
        else if (payload[1] == UDS_SECURITY_SEND_KEY)
        {
            printf("  -> OK     ACCES DEVERROUILLE\n");
        }
        else
        {
            printf("  -> OK     SecurityAccess\n");
        }
        return;
    }

    /* 0x54 : ClearDiagnosticInformation. */
    if ((len == 1u) &&
        (payload[0] == (UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION +
                        UDS_POSITIVE_RESPONSE_OFFSET)))
    {
        printf("  -> OK     defauts effaces\n");
        return;
    }

    /* 0x51 : ECUReset. */
    if ((len >= 2u) &&
        (payload[0] == (UDS_SID_ECU_RESET + UDS_POSITIVE_RESPONSE_OFFSET)))
    {
        printf("  -> OK     calculateur reinitialise (type 0x%02X)\n",
               payload[1]);
        return;
    }

    /* 0x7E : TesterPresent. */
    if ((len >= 1u) &&
        (payload[0] == (UDS_SID_TESTER_PRESENT +
                        UDS_POSITIVE_RESPONSE_OFFSET)))
    {
        printf("  -> OK     TesterPresent\n");
        return;
    }

    printf("  -> reponse non interpretee (%u octets)\n", len);
}

/* ------------------------------------------------------------------ */
/* Echange                                                             */
/* ------------------------------------------------------------------ */

/*
 * Emet une requete, affiche la reponse, et la recopie pour l'appelant.
 *
 * Retour : longueur de la reponse, 0 si aucune.
 */
static uint16_t request_into(const char *label,
                             const uint8_t *payload,
                             uint16_t payload_len,
                             uint8_t *copy,
                             uint16_t copy_capacity)
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
        return 0u;
    }

    r = diag_link_recv(&g_link, &response, &response_len,
                       RESPONSE_TIMEOUT_MS);

    if (r < 0)
    {
        printf("  -> ERREUR de reception\n");
        return 0u;
    }

    if (r == 0)
    {
        printf("  -> AUCUNE REPONSE (delai de %u ms expire)\n",
               RESPONSE_TIMEOUT_MS);
        return 0u;
    }

    g_answered++;
    print_uds_response(response, response_len);

    if ((copy != NULL) && (response_len <= copy_capacity))
    {
        memcpy(copy, response, response_len);
    }
    return response_len;
}

static void request(const char *label,
                    const uint8_t *payload,
                    uint16_t payload_len)
{
    (void)request_into(label, payload, payload_len, NULL, 0u);
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

    /* --- Session par defaut --- */
    {
        const uint8_t req[] = { UDS_SID_TESTER_PRESENT, 0x00 };
        request("TesterPresent (session par defaut)", req, sizeof(req));
    }
    {
        const uint8_t req[] = { UDS_SID_ECU_RESET, 0x01 };
        request("ECUReset en session par defaut -> doit etre refuse",
                req, sizeof(req));
    }

    /* --- Passage en session etendue --- */
    {
        const uint8_t req[] = { UDS_SID_DIAGNOSTIC_SESSION_CONTROL, 0x03 };
        request("DiagnosticSessionControl -> Extended", req, sizeof(req));
    }

    /* --- Lectures --- */
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
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0xF1, 0x90 };
        request("ReadDataByIdentifier -> VIN (transfert multi-trames)",
                req, sizeof(req));
    }

    /* --- Defauts --- */
    {
        const uint8_t req[] = { UDS_SID_READ_DTC_INFORMATION, 0x02, 0x09 };
        request("ReadDTCInformation -> defauts confirmes", req, sizeof(req));
    }

    /* --- La commande sensible est refusee sans deverrouillage --- */
    {
        const uint8_t req[] = { UDS_SID_ECU_RESET, 0x01 };
        request("ECUReset sans SecurityAccess -> doit etre refuse",
                req, sizeof(req));
    }

    /* --- SecurityAccess : mauvaise cle, puis bonne cle --- */
    {
        uint8_t resp[16];
        uint16_t n;
        uint32_t seed = 0u;
        uint32_t key;

        {
            const uint8_t req[] = { UDS_SID_SECURITY_ACCESS,
                                    UDS_SECURITY_REQUEST_SEED };
            n = request_into("SecurityAccess -> demande de graine",
                             req, sizeof(req), resp, sizeof(resp));
            if (n >= 6u)
            {
                seed = (((uint32_t)resp[2]) << 24) |
                       (((uint32_t)resp[3]) << 16) |
                       (((uint32_t)resp[4]) << 8) |
                       ((uint32_t)resp[5]);
            }
        }

        /* Cle volontairement fausse. */
        {
            uint8_t req[6];
            req[0] = UDS_SID_SECURITY_ACCESS;
            req[1] = UDS_SECURITY_SEND_KEY;
            req[2] = 0xDE; req[3] = 0xAD; req[4] = 0xBE; req[5] = 0xEF;
            request("SecurityAccess -> cle fausse", req, sizeof(req));
        }

        /* La graine a ete consommee : il faut en redemander une. */
        {
            const uint8_t req[] = { UDS_SID_SECURITY_ACCESS,
                                    UDS_SECURITY_REQUEST_SEED };
            n = request_into("SecurityAccess -> nouvelle graine",
                             req, sizeof(req), resp, sizeof(resp));
            if (n >= 6u)
            {
                seed = (((uint32_t)resp[2]) << 24) |
                       (((uint32_t)resp[3]) << 16) |
                       (((uint32_t)resp[4]) << 8) |
                       ((uint32_t)resp[5]);
            }
        }

        key = uds_demo_key_from_seed(seed);

        {
            uint8_t req[6];
            req[0] = UDS_SID_SECURITY_ACCESS;
            req[1] = UDS_SECURITY_SEND_KEY;
            req[2] = (uint8_t)((key >> 24) & 0xFFu);
            req[3] = (uint8_t)((key >> 16) & 0xFFu);
            req[4] = (uint8_t)((key >> 8) & 0xFFu);
            req[5] = (uint8_t)(key & 0xFFu);
            request("SecurityAccess -> cle correcte", req, sizeof(req));

            /* Rejeu immediat de la meme cle : aucune graine en attente. */
            request("SecurityAccess -> rejeu de la meme cle",
                    req, sizeof(req));
        }
    }

    /* --- Operations desormais autorisees --- */
    {
        const uint8_t req[] = { UDS_SID_CLEAR_DIAGNOSTIC_INFORMATION,
                                0xFF, 0xFF, 0xFF };
        request("ClearDiagnosticInformation -> tous les defauts",
                req, sizeof(req));
    }
    {
        const uint8_t req[] = { UDS_SID_READ_DTC_INFORMATION, 0x02, 0x09 };
        request("ReadDTCInformation -> apres effacement", req, sizeof(req));
    }
    {
        const uint8_t req[] = { UDS_SID_ECU_RESET, 0x01 };
        request("ECUReset apres deverrouillage -> doit etre accepte",
                req, sizeof(req));
    }

    /* --- Apres reinitialisation, tout est reverrouille --- */
    {
        const uint8_t req[] = { UDS_SID_ECU_RESET, 0x01 };
        request("ECUReset juste apres le reset -> refuse a nouveau",
                req, sizeof(req));
    }

    /* --- Chemins de refus divers --- */
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
