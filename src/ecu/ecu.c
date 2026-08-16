#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#include <net/if.h>

#include "isotp.h"

int main(void)
{
    int socket_fd;
    struct sockaddr_can addr;
    struct ifreq ifr;

    struct can_frame rx_frame;
    struct can_frame tx_frame;

    // 1. Creer le socket CAN
    socket_fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);

    if (socket_fd < 0)
    {
        perror("socket");
        return 1;
    }

    // 2. Selectionner vcan0
    strcpy(ifr.ifr_name, "vcan0");

    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl");
        close(socket_fd);
        return 1;
    }

    // 3. Associer le socket a l'interface CAN
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(socket_fd);
        return 1;
    }

    printf("ECU virtuel demarre\n");
    printf("En attente d'une requete sur 0x7E0...\n");

    while (1)
    {
        // 4. Attendre une trame CAN
        if (read(socket_fd, &rx_frame, sizeof(rx_frame)) < 0)
        {
            perror("read");
            break;
        }

        // L'ECU ne traite que les requetes 0x7E0
        if (rx_frame.can_id != 0x7E0)
        {
            continue;
        }

        printf("\nTrame recue\n");
        printf("ID : 0x%X\n", rx_frame.can_id);

        printf("DATA : ");

        for (int i = 0; i < rx_frame.can_dlc; i++)
        {
            printf("%02X ", rx_frame.data[i]);
        }

        printf("\n");

        /*
         * Decodage ISO-TP
         *
         * Toute la connaissance du format est desormais dans isotp.c.
         * L'ECU ne manipule plus le PCI lui-meme : il recoit une payload
         * deja validee, ou une erreur explicite.
         */

        const uint8_t *payload = NULL;
        uint8_t payload_length = 0;

        isotp_result_t isotp_res = isotp_decode_single_frame(rx_frame.data,
                                                            rx_frame.can_dlc,
                                                            &payload,
                                                            &payload_length);

        if (isotp_res != ISOTP_OK)
        {
            printf("ISO-TP : trame rejetee (%s)\n",
                   isotp_result_to_string(isotp_res));
            continue;
        }

        printf("ISO-TP : Single Frame\n");
        printf("Longueur payload : %u octets\n", payload_length);

        // Pour notre requete actuelle, on attend au moins 2 octets UDS
        if (payload_length < 2)
        {
            printf("Erreur : payload ISO-TP trop court\n");
            continue;
        }

        /*
         * Decodage UDS
         *
         * payload[0] et payload[1] : garantis presents par ISO-TP.
         */

        uint8_t uds_service = payload[0];
        uint8_t uds_subfunction = payload[1];

        printf("UDS Service : 0x%02X\n", uds_service);
        printf("UDS Sub-function : 0x%02X\n", uds_subfunction);

        /*
         * Service 0x10 :
         * DiagnosticSessionControl
         *
         * Sub-function 0x03 :
         * Extended Diagnostic Session
         */

        if ((uds_service == 0x10) &&
            (uds_subfunction == 0x03))
        {
            printf("UDS : demande Extended Diagnostic Session\n");

            /*
             * Reponse positive UDS :
             *
             * 0x50 = 0x10 + 0x40
             * 0x03 = session acceptee
             *
             * L'ECU construit uniquement la payload UDS.
             * C'est ISO-TP qui ajoute le PCI et le bourrage.
             */

            uint8_t uds_response[2];
            uint8_t tx_len = 0;

            uds_response[0] = (uint8_t)(uds_service + 0x40u);
            uds_response[1] = uds_subfunction;

            isotp_res = isotp_encode_single_frame(uds_response,
                                                  sizeof(uds_response),
                                                  tx_frame.data,
                                                  sizeof(tx_frame.data),
                                                  &tx_len);

            if (isotp_res != ISOTP_OK)
            {
                printf("ISO-TP : encodage impossible (%s)\n",
                       isotp_result_to_string(isotp_res));
                continue;
            }

            tx_frame.can_id = 0x7E8;
            tx_frame.can_dlc = tx_len;

            if (write(socket_fd, &tx_frame, sizeof(tx_frame)) !=
                sizeof(tx_frame))
            {
                perror("write");
                break;
            }

            printf("UDS : Extended Session acceptee\n");
            printf("Reponse envoyee sur 0x7E8\n");
        }
        else
        {
            printf("UDS : service ou sous-fonction non supporte\n");
        }
    }

    close(socket_fd);

    return 0;
}