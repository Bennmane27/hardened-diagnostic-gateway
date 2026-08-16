/*
 * diag_link.c
 *
 * Boucle de service d'une session ISO-TP sur socket CAN.
 */

#include "diag_link.h"

#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Traces                                                              */
/* ------------------------------------------------------------------ */

static void trace_frame(const diag_link_t *link,
                        const char *direction,
                        uint32_t can_id,
                        const uint8_t *data,
                        uint8_t len)
{
    uint8_t i;

    if (link->verbose == 0)
    {
        return;
    }

    printf("    %s %03X : ", direction, can_id);
    for (i = 0u; i < len; i++)
    {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

static int send_frame(diag_link_t *link, const uint8_t *data, uint8_t len)
{
    trace_frame(link, "TX", link->tx_can_id, data, len);
    return can_socket_send(link->sock, link->tx_can_id, data, len);
}

/* ------------------------------------------------------------------ */
/* Cycle de vie                                                        */
/* ------------------------------------------------------------------ */

void diag_link_init(diag_link_t *link,
                    can_socket_t *sock,
                    uint32_t tx_can_id,
                    uint32_t rx_can_id,
                    int verbose)
{
    if (link == NULL)
    {
        return;
    }

    link->sock       = sock;
    link->tx_can_id  = tx_can_id;
    link->rx_can_id  = rx_can_id;
    link->verbose    = verbose;
    link->last_error = ISOTP_OK;

    isotp_rx_init(&link->rx);
    isotp_tx_init(&link->tx);
}

/* ------------------------------------------------------------------ */
/* Progression de l'emission                                           */
/* ------------------------------------------------------------------ */

/*
 * Fait avancer l'emission en cours : envoie les Consecutive Frames dont
 * l'ecart STmin est ecoule, detecte l'expiration de N_Bs.
 *
 * Retour : 0 normal, -1 abandon.
 */
static int drive_tx(diag_link_t *link, uint32_t now_ms)
{
    isotp_tx_result_t out;
    int guard;

    if (link->tx.state == ISOTP_TX_IDLE)
    {
        return 0;
    }

    /*
     * Boucle bornee. Un message de 4095 octets tient en 585 Consecutive
     * Frames ; 700 tours couvrent le pire cas avec de la marge, et
     * garantissent qu'aucune situation ne fait tourner sans fin.
     */
    for (guard = 0; guard < 700; guard++)
    {
        if (isotp_tx_poll(&link->tx, now_ms, &out) != ISOTP_OK)
        {
            return -1;
        }

        if (out.event == ISOTP_TX_EVENT_SEND_FRAME)
        {
            if (send_frame(link, out.frame, out.frame_len) != 0)
            {
                return -1;
            }
            continue;
        }

        if (out.event == ISOTP_TX_EVENT_ABORTED)
        {
            link->last_error = out.reason;
            return -1;
        }

        /* WAIT ou NONE : plus rien a faire pour l'instant. */
        return 0;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* Traitement d'une trame recue                                        */
/* ------------------------------------------------------------------ */

/*
 * Retour : 1 message complet disponible, 0 rien, -1 erreur.
 */
static int handle_frame(diag_link_t *link,
                        const uint8_t *data,
                        uint8_t len,
                        uint32_t now_ms,
                        const uint8_t **out_payload,
                        uint16_t *out_payload_len)
{
    isotp_frame_type_t type;
    isotp_rx_result_t rx_out;
    isotp_tx_result_t tx_out;

    if (isotp_get_frame_type(data, len, &type) != ISOTP_OK)
    {
        return 0;
    }

    /*
     * Aiguillage essentiel : un Flow Control concerne NOTRE emission,
     * pas notre reception. L'envoyer au reassembleur le ferait rejeter
     * a tort et bloquerait tout transfert multi-trames sortant.
     */
    if ((type == ISOTP_FRAME_FLOW_CONTROL) &&
        (link->tx.state != ISOTP_TX_IDLE))
    {
        if (isotp_tx_on_flow_control(&link->tx, data, len,
                                     now_ms, &tx_out) != ISOTP_OK)
        {
            return -1;
        }

        if (tx_out.event == ISOTP_TX_EVENT_SEND_FRAME)
        {
            if (send_frame(link, tx_out.frame, tx_out.frame_len) != 0)
            {
                return -1;
            }
            return drive_tx(link, now_ms) == 0 ? 0 : -1;
        }

        if (tx_out.event == ISOTP_TX_EVENT_ABORTED)
        {
            link->last_error = tx_out.reason;
            return -1;
        }

        return 0;
    }

    if (isotp_rx_process(&link->rx, data, len, now_ms, &rx_out) != ISOTP_OK)
    {
        return -1;
    }

    switch (rx_out.event)
    {
    case ISOTP_RX_EVENT_SEND_FLOW_CONTROL:
        if (send_frame(link, rx_out.fc_frame, rx_out.fc_len) != 0)
        {
            return -1;
        }
        return 0;

    case ISOTP_RX_EVENT_MESSAGE_READY:
        *out_payload     = rx_out.message;
        *out_payload_len = rx_out.message_len;
        return 1;

    case ISOTP_RX_EVENT_ABORTED:
        link->last_error = rx_out.reason;
        if (link->verbose != 0)
        {
            printf("    ISO-TP : transfert abandonne (%s)\n",
                   isotp_result_to_string(rx_out.reason));
        }
        return 0;

    default:
        if ((rx_out.reason != ISOTP_OK) && (link->verbose != 0))
        {
            printf("    ISO-TP : trame ignoree (%s)\n",
                   isotp_result_to_string(rx_out.reason));
        }
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

int diag_link_poll(diag_link_t *link,
                   const uint8_t **out_payload,
                   uint16_t *out_payload_len)
{
    uint8_t  data[ISOTP_CAN_FRAME_SIZE];
    uint32_t can_id = 0u;
    uint8_t  len = 0u;
    uint32_t now_ms;
    int      n;
    isotp_rx_result_t rx_out;

    if ((link == NULL) || (out_payload == NULL) || (out_payload_len == NULL))
    {
        return -1;
    }

    n = can_socket_recv(link->sock, &can_id, data, &len);

    now_ms = can_monotonic_ms();

    if (n < 0)
    {
        return -1;
    }

    if (n == 0)
    {
        /* Aucune trame : c'est le moment de verifier les temporisations. */
        (void)isotp_rx_poll_timeout(&link->rx, now_ms, &rx_out);
        if (rx_out.event == ISOTP_RX_EVENT_ABORTED)
        {
            link->last_error = rx_out.reason;
            if (link->verbose != 0)
            {
                printf("    ISO-TP : reception abandonnee (%s)\n",
                       isotp_result_to_string(rx_out.reason));
            }
        }
        (void)drive_tx(link, now_ms);
        return 0;
    }

    if (can_id != link->rx_can_id)
    {
        return 0;
    }

    trace_frame(link, "RX", can_id, data, len);

    return handle_frame(link, data, len, now_ms,
                        out_payload, out_payload_len);
}

int diag_link_send(diag_link_t *link,
                   const uint8_t *payload,
                   uint16_t payload_len)
{
    isotp_tx_result_t out;
    uint32_t now_ms;
    uint32_t deadline;
    const uint8_t *ignored_payload = NULL;
    uint16_t ignored_len = 0u;

    if ((link == NULL) || (payload == NULL))
    {
        return -1;
    }

    now_ms = can_monotonic_ms();

    if (isotp_tx_start(&link->tx, payload, payload_len,
                       now_ms, &out) != ISOTP_OK)
    {
        link->last_error = ISOTP_ERR_INVALID_LENGTH;
        return -1;
    }

    if (out.event != ISOTP_TX_EVENT_SEND_FRAME)
    {
        return -1;
    }

    if (send_frame(link, out.frame, out.frame_len) != 0)
    {
        return -1;
    }

    /* Message court : tout est parti en une trame. */
    if (link->tx.state == ISOTP_TX_IDLE)
    {
        return 0;
    }

    /*
     * Multi-trames : il faut maintenant recevoir le Flow Control et
     * emettre les Consecutive Frames. La borne globale evite qu'un pair
     * silencieux ne bloque indefiniment, en plus de N_Bs.
     */
    deadline = ISOTP_N_BS_TIMEOUT_MS * 4u;

    while (link->tx.state != ISOTP_TX_IDLE)
    {
        if (diag_link_poll(link, &ignored_payload, &ignored_len) < 0)
        {
            return -1;
        }

        if ((uint32_t)(can_monotonic_ms() - now_ms) >= deadline)
        {
            link->last_error = ISOTP_ERR_TIMEOUT;
            isotp_tx_reset(&link->tx);
            return -1;
        }
    }

    return 0;
}

int diag_link_recv(diag_link_t *link,
                   const uint8_t **out_payload,
                   uint16_t *out_payload_len,
                   uint32_t timeout_ms)
{
    uint32_t start;
    int r;

    if ((link == NULL) || (out_payload == NULL) || (out_payload_len == NULL))
    {
        return -1;
    }

    start = can_monotonic_ms();

    for (;;)
    {
        r = diag_link_poll(link, out_payload, out_payload_len);

        if (r != 0)
        {
            return r;   /* 1 message recu, -1 erreur */
        }

        if ((uint32_t)(can_monotonic_ms() - start) >= timeout_ms)
        {
            return 0;
        }
    }
}
