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
#include "uds.h"
#include "ecu_data.h"

int main(void)
{
    int socket_fd;
    struct sockaddr_can addr;
    struct ifreq ifr;

    struct can_frame rx_frame;
    struct can_frame tx_frame;

    // Donnees simulees du calculateur (couche application).
    ecu_data_t ecu_data;
    ecu_data_init(&ecu_data);

    // Contexte du serveur UDS : porte la session courante.
    uds_context_t uds_ctx;
    uds_init(&uds_ctx);

    // Le serveur UDS ne connait pas les donnees : on lui branche la
    // source applicative. C'est la seule liaison entre les deux.
    uds_set_did_provider(&uds_ctx, ecu_data_read_did, &ecu_data);

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
    // memset : le reste de la structure doit etre a zero, pas du contenu
    // de pile indetermine.
    memset(&addr, 0, sizeof(addr));
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

        // Les grandeurs simulees avancent d'un pas a chaque requete.
        ecu_data_tick(&ecu_data);

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

        /*
         * Traitement UDS
         *
         * L'ECU ne decode plus lui-meme les services : il transmet la
         * payload au serveur UDS et recoit une reponse deja formee,
         * positive ou negative. La validation des longueurs et des
         * sous-fonctions appartient a uds.c.
         */

        uint8_t uds_response[UDS_MAX_RESPONSE_SIZE];
        uint8_t uds_response_len = 0;

        uds_result_t uds_res = uds_handle_request(&uds_ctx,
                                                  payload,
                                                  payload_length,
                                                  uds_response,
                                                  sizeof(uds_response),
                                                  &uds_response_len);

        if (uds_res == UDS_NO_RESPONSE)
        {
            printf("UDS : aucune reponse a emettre\n");
            printf("Session courante : %s\n",
                   uds_session_to_string(uds_ctx.session));
            continue;
        }

        if (uds_res != UDS_OK)
        {
            printf("UDS : erreur interne (%s)\n",
                   uds_result_to_string(uds_res));
            continue;
        }

        // Trace lisible : reponse positive ou negative ?
        if (uds_response[0] == UDS_NEGATIVE_RESPONSE_SID)
        {
            printf("UDS : reponse NEGATIVE au service 0x%02X -> 0x%02X (%s)\n",
                   uds_response[1],
                   uds_response[2],
                   uds_nrc_to_string(uds_response[2]));
        }
        else
        {
            printf("UDS : reponse positive 0x%02X\n", uds_response[0]);
            printf("Session courante : %s\n",
                   uds_session_to_string(uds_ctx.session));
        }

        /*
         * La reponse UDS est ensuite encapsulee par ISO-TP, qui ajoute
         * le PCI et le bourrage.
         */

        uint8_t tx_len = 0;

        isotp_res = isotp_encode_single_frame(uds_response,
                                              uds_response_len,
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

        printf("Reponse envoyee sur 0x7E8\n");
    }

    close(socket_fd);

    return 0;
}