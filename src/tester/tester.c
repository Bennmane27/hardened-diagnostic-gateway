#include <stdio.h>
#include <stdlib.h>
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

    struct can_frame tx_frame;
    struct can_frame rx_frame;

    // 1. Creer un socket CAN
    socket_fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);

    if (socket_fd < 0)
    {
        perror("socket");
        return 1;
    }

    // 2. Selectionner l'interface vcan0
    strcpy(ifr.ifr_name, "vcan0");

    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl");
        close(socket_fd);
        return 1;
    }

    // 3. Associer le socket a vcan0
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(socket_fd);
        return 1;
    }

    /*
     * Construction de la requete.
     *
     * Le tester ne decrit plus que la payload UDS :
     *
     * 0x10 = DiagnosticSessionControl
     * 0x03 = Extended Diagnostic Session
     *
     * ISO-TP se charge du PCI (0x02) et du bourrage.
     */

    uint8_t uds_request[2] = { 0x10, 0x03 };
    uint8_t tx_len = 0;

    isotp_result_t isotp_res = isotp_encode_single_frame(uds_request,
                                                        sizeof(uds_request),
                                                        tx_frame.data,
                                                        sizeof(tx_frame.data),
                                                        &tx_len);

    if (isotp_res != ISOTP_OK)
    {
        printf("ISO-TP : encodage impossible (%s)\n",
               isotp_result_to_string(isotp_res));
        close(socket_fd);
        return 1;
    }

    tx_frame.can_id = 0x7E0;
    tx_frame.can_dlc = tx_len;

    // 4. Envoyer la requete
    if (write(socket_fd, &tx_frame, sizeof(tx_frame)) != sizeof(tx_frame))
    {
        perror("write");
        close(socket_fd);
        return 1;
    }

    printf("Requete UDS envoyee sur 0x7E0\n");
    printf("UDS : DiagnosticSessionControl -> Extended Session\n");
    printf("En attente de la reponse ECU...\n");

    // 5. Attendre la reponse ECU
    while (1)
    {
        if (read(socket_fd, &rx_frame, sizeof(rx_frame)) < 0)
        {
            perror("read");
            close(socket_fd);
            return 1;
        }

        // On ignore toutes les trames sauf celles de l'ECU
        if (rx_frame.can_id == 0x7E8)
        {
            printf("\nReponse ECU recue\n");
            printf("ID : 0x%X\n", rx_frame.can_id);

            printf("DATA : ");

            for (int i = 0; i < rx_frame.can_dlc; i++)
            {
                printf("%02X ", rx_frame.data[i]);
            }

            printf("\n");

            /*
             * Decodage ISO-TP de la reponse.
             *
             * Reponse attendue apres decodage :
             *
             * 50 = reponse positive au service 0x10
             * 03 = Extended Diagnostic Session
             */

            const uint8_t *payload = NULL;
            uint8_t payload_length = 0;

            isotp_res = isotp_decode_single_frame(rx_frame.data,
                                                  rx_frame.can_dlc,
                                                  &payload,
                                                  &payload_length);

            if (isotp_res != ISOTP_OK)
            {
                printf("ISO-TP : reponse rejetee (%s)\n",
                       isotp_result_to_string(isotp_res));
                break;
            }

            printf("ISO-TP : Single Frame, %u octets de payload\n",
                   payload_length);

            if ((payload_length >= 2) &&
                (payload[0] == 0x50) &&
                (payload[1] == 0x03))
            {
                printf("UDS : Extended Diagnostic Session acceptee\n");
            }
            else
            {
                printf("UDS : reponse inattendue\n");
            }

            break;
        }
    }

    close(socket_fd);

    return 0;
}