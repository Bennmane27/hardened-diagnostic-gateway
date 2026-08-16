/*
 * tester.c
 *
 * Client de diagnostic.
 *
 * Envoie une sequence de requetes UDS a l'ECU virtuel et decode les
 * reponses, positives comme negatives. C'est le seul fichier du tester
 * qui connaisse SocketCAN ; le formatage des messages appartient aux
 * couches isotp et uds.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#include <net/if.h>

#include "isotp.h"
#include "uds.h"
#include "ecu_data.h"

#define CAN_ID_TESTER_TO_ECU   0x7E0u
#define CAN_ID_ECU_TO_TESTER   0x7E8u

/* Delai d'attente d'une reponse, en secondes. */
#define RESPONSE_TIMEOUT_S     2

/* ------------------------------------------------------------------ */
/* Affichage                                                           */
/* ------------------------------------------------------------------ */

static void print_hex(const uint8_t *data, uint8_t len)
{
    uint8_t i;
    for (i = 0u; i < len; i++)
    {
        printf("%02X ", data[i]);
    }
}

/*
 * Decode une reponse UDS deja extraite de son enveloppe ISO-TP.
 *
 * Le test de la reponse negative vient en premier : 0x7F n'est pas un
 * service, c'est un marqueur de rejet. L'oublier ferait passer un refus
 * pour une reponse incomprehensible.
 */
static void print_uds_response(const uint8_t *payload, uint8_t len)
{
    if ((len == UDS_NEGATIVE_RESPONSE_LEN) &&
        (payload[0] == UDS_NEGATIVE_RESPONSE_SID))
    {
        printf("  -> REFUS  service 0x%02X, NRC 0x%02X (%s)\n",
               payload[1], payload[2], uds_nrc_to_string(payload[2]));
        return;
    }

    /* 0x50 : reponse positive a DiagnosticSessionControl. */
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

    /* 0x62 : reponse positive a ReadDataByIdentifier. */
    if ((len >= 3u) &&
        (payload[0] == (UDS_SID_READ_DATA_BY_IDENTIFIER +
                        UDS_POSITIVE_RESPONSE_OFFSET)))
    {
        uint16_t did = (uint16_t)(((uint16_t)payload[1] << 8) | payload[2]);
        uint8_t  data_len = (uint8_t)(len - 3u);

        printf("  -> OK     DID 0x%04X (%s) = ",
               did, ecu_data_did_to_string(did));
        print_hex(&payload[3], data_len);

        /* Interpretation des grandeurs numeriques connues. */
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
        printf("\n");
        return;
    }

    printf("  -> reponse non interpretee\n");
}

/* ------------------------------------------------------------------ */
/* Echange requete / reponse                                           */
/* ------------------------------------------------------------------ */

/*
 * Emet une payload UDS et attend la reponse de l'ECU.
 *
 * Retour : 0 si une reponse a ete traitee, -1 sur erreur ou expiration.
 *
 * Le socket porte un delai de reception : sans lui, une requete sans
 * reponse (bit de suppression, ECU muet) bloquerait le tester
 * indefiniment. C'est la premiere forme de gestion de timeout du
 * projet, cote client.
 */
static int send_request(int socket_fd,
                        const char *label,
                        const uint8_t *request,
                        uint8_t request_len)
{
    struct can_frame tx_frame;
    struct can_frame rx_frame;
    uint8_t tx_len = 0u;
    isotp_result_t isotp_res;

    printf("\n%s\n", label);

    isotp_res = isotp_encode_single_frame(request, request_len,
                                          tx_frame.data,
                                          (uint8_t)sizeof(tx_frame.data),
                                          &tx_len);
    if (isotp_res != ISOTP_OK)
    {
        printf("  ISO-TP : encodage impossible (%s)\n",
               isotp_result_to_string(isotp_res));
        return -1;
    }

    memset(&tx_frame.__pad, 0, sizeof(tx_frame.__pad));
    tx_frame.can_id  = CAN_ID_TESTER_TO_ECU;
    tx_frame.can_dlc = tx_len;

    printf("  TX 7E0 : ");
    print_hex(tx_frame.data, tx_frame.can_dlc);
    printf("\n");

    if (write(socket_fd, &tx_frame, sizeof(tx_frame)) !=
        (ssize_t)sizeof(tx_frame))
    {
        perror("write");
        return -1;
    }

    /* On ignore tout ce qui ne vient pas de l'ECU. */
    for (;;)
    {
        ssize_t n = read(socket_fd, &rx_frame, sizeof(rx_frame));

        if (n < 0)
        {
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
            {
                printf("  -> AUCUNE REPONSE (delai de %d s expire)\n",
                       RESPONSE_TIMEOUT_S);
                return -1;
            }
            perror("read");
            return -1;
        }

        if (rx_frame.can_id != CAN_ID_ECU_TO_TESTER)
        {
            continue;
        }

        printf("  RX 7E8 : ");
        print_hex(rx_frame.data, rx_frame.can_dlc);
        printf("\n");

        {
            const uint8_t *payload = NULL;
            uint8_t payload_len = 0u;

            isotp_res = isotp_decode_single_frame(rx_frame.data,
                                                  rx_frame.can_dlc,
                                                  &payload,
                                                  &payload_len);
            if (isotp_res != ISOTP_OK)
            {
                printf("  ISO-TP : reponse rejetee (%s)\n",
                       isotp_result_to_string(isotp_res));
                return -1;
            }

            print_uds_response(payload, payload_len);
        }
        return 0;
    }
}

/* ------------------------------------------------------------------ */

int main(void)
{
    int socket_fd;
    struct sockaddr_can addr;
    struct ifreq ifr;
    struct timeval timeout;

    socket_fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (socket_fd < 0)
    {
        perror("socket");
        return 1;
    }

    strcpy(ifr.ifr_name, "vcan0");
    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl");
        close(socket_fd);
        return 1;
    }

    // memset : le reste de la structure doit etre a zero, pas du contenu
    // de pile indetermine.
    memset(&addr, 0, sizeof(addr));
    addr.can_family  = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(socket_fd);
        return 1;
    }

    /* Delai de reception, pour ne jamais bloquer indefiniment. */
    timeout.tv_sec  = RESPONSE_TIMEOUT_S;
    timeout.tv_usec = 0;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt");
        close(socket_fd);
        return 1;
    }

    printf("=== Tester de diagnostic ===\n");

    /* --- Passage en session etendue --- */
    {
        const uint8_t req[] = { UDS_SID_DIAGNOSTIC_SESSION_CONTROL, 0x03 };
        (void)send_request(socket_fd,
                           "[1] DiagnosticSessionControl -> Extended",
                           req, sizeof(req));
    }

    /* --- Identification du calculateur --- */
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0xF1, 0x89 };
        (void)send_request(socket_fd,
                           "[2] ReadDataByIdentifier -> version logicielle",
                           req, sizeof(req));
    }
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0xF1, 0x8C };
        (void)send_request(socket_fd,
                           "[3] ReadDataByIdentifier -> numero de serie",
                           req, sizeof(req));
    }

    /* --- Grandeurs vives --- */
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0x01, 0x00 };
        (void)send_request(socket_fd,
                           "[4] ReadDataByIdentifier -> regime moteur",
                           req, sizeof(req));
    }
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0x01, 0x02 };
        (void)send_request(socket_fd,
                           "[5] ReadDataByIdentifier -> temperature moteur",
                           req, sizeof(req));
    }
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0x01, 0x03 };
        (void)send_request(socket_fd,
                           "[6] ReadDataByIdentifier -> tension batterie",
                           req, sizeof(req));
    }

    /* --- Cas de refus --- */
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0xF1, 0x90 };
        (void)send_request(socket_fd,
                           "[7] ReadDataByIdentifier -> VIN "
                           "(17 octets : ne tient pas en Single Frame)",
                           req, sizeof(req));
    }
    {
        const uint8_t req[] = { UDS_SID_READ_DATA_BY_IDENTIFIER, 0xAB, 0xCD };
        (void)send_request(socket_fd,
                           "[8] ReadDataByIdentifier -> identifiant inconnu",
                           req, sizeof(req));
    }
    {
        const uint8_t req[] = { 0x99, 0x00 };
        (void)send_request(socket_fd,
                           "[9] Service inexistant 0x99",
                           req, sizeof(req));
    }

    printf("\n=== Fin de la sequence ===\n");

    close(socket_fd);
    return 0;
}
