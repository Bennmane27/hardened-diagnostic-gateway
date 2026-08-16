/*
 * diag_link.h
 *
 * Liaison de diagnostic : une session ISO-TP au-dessus d'un socket CAN.
 *
 * Ce module reunit les deux contextes ISO-TP (reception et emission) et
 * la boucle qui les alimente. Il existe parce que l'ECU et le tester
 * avaient besoin exactement de la meme boucle, avec seulement les
 * identifiants CAN inverses.
 *
 * Il depend de can_socket, donc de Linux. Les couches isotp et uds
 * restent en dessous et n'en savent rien.
 */

#ifndef DIAG_LINK_H
#define DIAG_LINK_H

#include <stdint.h>

#include "can_socket.h"
#include "isotp.h"

typedef struct
{
    can_socket_t *sock;

    uint32_t tx_can_id;   /* identifiant sur lequel on emet   */
    uint32_t rx_can_id;   /* identifiant que l'on ecoute      */

    isotp_rx_context_t rx;
    isotp_tx_context_t tx;

    /* Affiche chaque trame emise et recue. Utile en demonstration. */
    int verbose;

    /* Derniere raison d'abandon, pour les traces. */
    isotp_result_t last_error;
} diag_link_t;

void diag_link_init(diag_link_t *link,
                    can_socket_t *sock,
                    uint32_t tx_can_id,
                    uint32_t rx_can_id,
                    int verbose);

/*
 * Emet un message complet, en segmentant si necessaire.
 *
 * Bloquant : la fonction ne rend la main qu'une fois le message
 * entierement transmis, ou le transfert abandonne.
 *
 * Retour :  0  message transmis
 *          -1  echec (voir link->last_error)
 */
int diag_link_send(diag_link_t *link,
                   const uint8_t *payload,
                   uint16_t payload_len);

/*
 * Attend un message complet, en reassemblant si necessaire.
 *
 * Emet automatiquement les Flow Control attendus par l'emetteur d'en
 * face, et surveille l'expiration de N_Cr.
 *
 * out_payload pointe dans le contexte de la liaison : la donnee reste
 * valide jusqu'au prochain appel.
 *
 * Retour :  1  message recu
 *           0  delai global expire
 *          -1  erreur
 */
int diag_link_recv(diag_link_t *link,
                   const uint8_t **out_payload,
                   uint16_t *out_payload_len,
                   uint32_t timeout_ms);

/*
 * Fait tourner la liaison une fois, sans attendre de message complet.
 * Sert a une boucle de service qui veut garder la main.
 *
 * Retour :  1  un message complet est disponible
 *           0  rien pour l'instant
 *          -1  erreur
 */
int diag_link_poll(diag_link_t *link,
                   const uint8_t **out_payload,
                   uint16_t *out_payload_len);

#endif /* DIAG_LINK_H */
