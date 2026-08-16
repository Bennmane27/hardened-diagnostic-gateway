/*
 * can_socket.h
 *
 * Adaptateur SocketCAN.
 *
 * SEULE couche du projet, avec les deux mains applicatifs, autorisee a
 * inclure des headers Linux. Tout ce qui est au-dessus (isotp, uds)
 * ignore jusqu'a l'existence de SocketCAN.
 *
 * Ce module a ete cree quand un deuxieme appelant a eu besoin de la
 * meme logique, pas avant : voir la decision D2 dans
 * docs/PROJECT_MEMORY.md.
 *
 * Pour porter le projet sur microcontroleur, c'est ce fichier qu'il
 * faut reecrire, et lui seul.
 */

#ifndef CAN_SOCKET_H
#define CAN_SOCKET_H

#include <stdint.h>

typedef struct
{
    int fd;
} can_socket_t;

/*
 * Ouvre un socket CAN brut et l'attache a une interface.
 *
 * rx_timeout_ms : delai au-dela duquel une reception rend la main sans
 *                 trame. Indispensable : sans lui, la boucle ne pourrait
 *                 jamais verifier l'expiration des temporisations ISO-TP.
 *
 * Retour : 0 si ouvert, -1 sinon (message deja affiche).
 */
int can_socket_open(can_socket_t *sock,
                    const char *interface_name,
                    uint32_t rx_timeout_ms);

void can_socket_close(can_socket_t *sock);

/* Retour : 0 si emise, -1 sinon. */
int can_socket_send(can_socket_t *sock,
                    uint32_t can_id,
                    const uint8_t *data,
                    uint8_t len);

/*
 * Attend une trame.
 *
 * Retour :  1  une trame a ete recue
 *           0  delai expire, aucune trame
 *          -1  erreur
 */
int can_socket_recv(can_socket_t *sock,
                    uint32_t *out_can_id,
                    uint8_t *out_data,
                    uint8_t *out_len);

/*
 * Horloge monotone en millisecondes.
 *
 * Monotone, et non "heure du jour" : elle ne recule jamais, meme si
 * l'horloge systeme est corrigee. Une temporisation protocolaire basee
 * sur l'heure murale pourrait sauter ou repartir en arriere.
 */
uint32_t can_monotonic_ms(void);

#endif /* CAN_SOCKET_H */
