/*
 * isotp_tx.c
 *
 * Emission ISO-TP : segmentation d'un message en plusieurs trames.
 *
 * Machine a etats :
 *
 *   IDLE --- message <= 7 octets ---> IDLE           (une Single Frame)
 *   IDLE --- message  > 7 octets ---> WAIT_FLOW_CONTROL (First Frame emise)
 *
 *   WAIT_FLOW_CONTROL --- FC ContinueToSend ---> SENDING
 *   WAIT_FLOW_CONTROL --- FC Wait ------------> WAIT_FLOW_CONTROL
 *   WAIT_FLOW_CONTROL --- FC Overflow --------> IDLE (abandon)
 *   WAIT_FLOW_CONTROL --- N_Bs expire --------> IDLE (abandon)
 *
 *   SENDING --- STmin ecoule, reste des octets ---> SENDING
 *   SENDING --- dernier octet emis --------------> IDLE (termine)
 *
 * Le temps n'est jamais lu ici : il arrive en parametre. La couche est
 * donc testable sans attendre, et portable sans horloge systeme.
 */

#include "isotp.h"

#define PCI_TYPE_SHIFT   4u
#define PCI_LOW_MASK     0x0Fu

#define FF_PCI_LEN       2u
#define CF_PCI_LEN       1u

/* ------------------------------------------------------------------ */
/* Utilitaires internes                                                */
/* ------------------------------------------------------------------ */

static void tx_result_clear(isotp_tx_result_t *out)
{
    uint8_t i;

    out->event     = ISOTP_TX_EVENT_NONE;
    out->frame_len = 0u;
    out->reason    = ISOTP_OK;

    for (i = 0u; i < ISOTP_CAN_FRAME_SIZE; i++)
    {
        out->frame[i] = 0u;
    }
}

static void tx_go_idle(isotp_tx_context_t *ctx)
{
    ctx->state                = ISOTP_TX_IDLE;
    ctx->total_length         = 0u;
    ctx->sent_length          = 0u;
    ctx->next_sequence_number = 0u;
    ctx->block_size           = 0u;
    ctx->frames_in_block      = 0u;
    ctx->stmin_ms             = 0u;
}

/*
 * Remplit la trame de sortie a partir de la position courante dans le
 * message : construit une Consecutive Frame.
 */
static void build_consecutive_frame(isotp_tx_context_t *ctx,
                                    isotp_tx_result_t *out)
{
    uint16_t remaining;
    uint8_t  copy_len;
    uint8_t  i;

    remaining = (uint16_t)(ctx->total_length - ctx->sent_length);

    copy_len = ISOTP_CF_MAX_PAYLOAD;
    if ((uint16_t)copy_len > remaining)
    {
        copy_len = (uint8_t)remaining;
    }

    out->frame[0] =
        (uint8_t)(((uint8_t)ISOTP_FRAME_CONSECUTIVE << PCI_TYPE_SHIFT) |
                  (ctx->next_sequence_number & PCI_LOW_MASK));

    for (i = 0u; i < copy_len; i++)
    {
        out->frame[CF_PCI_LEN + i] = ctx->buffer[ctx->sent_length + i];
    }
    for (i = (uint8_t)(CF_PCI_LEN + copy_len); i < ISOTP_CAN_FRAME_SIZE; i++)
    {
        out->frame[i] = ISOTP_PADDING_BYTE;
    }

    out->frame_len = ISOTP_CAN_FRAME_SIZE;
    out->event     = ISOTP_TX_EVENT_SEND_FRAME;

    ctx->sent_length = (uint16_t)(ctx->sent_length + copy_len);
    ctx->next_sequence_number =
        (uint8_t)((ctx->next_sequence_number + 1u) & PCI_LOW_MASK);
    ctx->frames_in_block++;
    ctx->stat_frames++;
}

/* ------------------------------------------------------------------ */
/* Cycle de vie                                                        */
/* ------------------------------------------------------------------ */

void isotp_tx_init(isotp_tx_context_t *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    tx_go_idle(ctx);
    ctx->last_frame_time_ms = 0u;
    ctx->wait_start_ms      = 0u;
    ctx->stat_messages      = 0u;
    ctx->stat_frames        = 0u;
    ctx->stat_timeouts      = 0u;
}

void isotp_tx_reset(isotp_tx_context_t *ctx)
{
    if (ctx != NULL)
    {
        tx_go_idle(ctx);
    }
}

/* ------------------------------------------------------------------ */
/* Demarrage                                                           */
/* ------------------------------------------------------------------ */

isotp_result_t isotp_tx_start(isotp_tx_context_t *ctx,
                              const uint8_t *payload,
                              uint16_t payload_len,
                              uint32_t now_ms,
                              isotp_tx_result_t *out)
{
    uint16_t i;
    isotp_result_t res;

    if ((ctx == NULL) || (payload == NULL) || (out == NULL))
    {
        return ISOTP_ERR_NULL_POINTER;
    }

    tx_result_clear(out);

    /* Un transfert deja en cours ne doit pas etre ecrase en silence. */
    if (ctx->state != ISOTP_TX_IDLE)
    {
        return ISOTP_ERR_BUSY;
    }

    if (payload_len == 0u)
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    if (payload_len > (uint16_t)ISOTP_MAX_PAYLOAD_SIZE)
    {
        return ISOTP_ERR_OVERFLOW;
    }

    /* --- Cas simple : tout tient dans une Single Frame. --- */
    if (payload_len <= ISOTP_SF_MAX_PAYLOAD)
    {
        res = isotp_encode_single_frame(payload,
                                        (uint8_t)payload_len,
                                        out->frame,
                                        ISOTP_CAN_FRAME_SIZE,
                                        &out->frame_len);
        if (res != ISOTP_OK)
        {
            return res;
        }

        out->event = ISOTP_TX_EVENT_SEND_FRAME;
        ctx->stat_frames++;
        ctx->stat_messages++;
        tx_go_idle(ctx);
        return ISOTP_OK;
    }

    /* --- Cas multi-trames : on copie puis on emet la First Frame. --- */
    for (i = 0u; i < payload_len; i++)
    {
        ctx->buffer[i] = payload[i];
    }

    ctx->total_length         = payload_len;
    ctx->sent_length          = ISOTP_FF_FIRST_PAYLOAD;
    ctx->next_sequence_number = 1u;
    ctx->frames_in_block      = 0u;
    ctx->state                = ISOTP_TX_WAIT_FLOW_CONTROL;
    ctx->wait_start_ms        = now_ms;
    ctx->last_frame_time_ms   = now_ms;

    /*
     * FF_DL sur 12 bits : les 4 bits bas du premier octet portent les
     * bits 11..8 de la longueur, le second octet porte les bits 7..0.
     *
     * Exemple pour 20 octets (0x014) : 10 14.
     */
    out->frame[0] = (uint8_t)(((uint8_t)ISOTP_FRAME_FIRST << PCI_TYPE_SHIFT) |
                              (uint8_t)((payload_len >> 8) & PCI_LOW_MASK));
    out->frame[1] = (uint8_t)(payload_len & 0xFFu);

    for (i = 0u; i < ISOTP_FF_FIRST_PAYLOAD; i++)
    {
        out->frame[FF_PCI_LEN + i] = payload[i];
    }

    out->frame_len = ISOTP_CAN_FRAME_SIZE;
    out->event     = ISOTP_TX_EVENT_SEND_FRAME;

    ctx->stat_frames++;
    return ISOTP_OK;
}

/* ------------------------------------------------------------------ */
/* Reception d'un Flow Control                                         */
/* ------------------------------------------------------------------ */

isotp_result_t isotp_tx_on_flow_control(isotp_tx_context_t *ctx,
                                        const uint8_t *frame,
                                        uint8_t frame_len,
                                        uint32_t now_ms,
                                        isotp_tx_result_t *out)
{
    isotp_flow_status_t status;
    uint8_t block_size;
    uint8_t stmin;
    isotp_result_t res;

    if ((ctx == NULL) || (frame == NULL) || (out == NULL))
    {
        return ISOTP_ERR_NULL_POINTER;
    }

    tx_result_clear(out);

    /*
     * Un Flow Control alors qu'aucune emission n'attend est ignore. Un
     * pair malveillant ne doit pas pouvoir declencher une emission.
     */
    if (ctx->state != ISOTP_TX_WAIT_FLOW_CONTROL)
    {
        out->reason = ISOTP_ERR_UNEXPECTED_FRAME;
        return ISOTP_OK;
    }

    res = isotp_decode_flow_control(frame, frame_len,
                                    &status, &block_size, &stmin);
    if (res != ISOTP_OK)
    {
        out->event  = ISOTP_TX_EVENT_ABORTED;
        out->reason = res;
        tx_go_idle(ctx);
        return ISOTP_OK;
    }

    switch (status)
    {
    case ISOTP_FC_CONTINUE_TO_SEND:
        ctx->block_size      = block_size;
        ctx->stmin_ms        = isotp_stmin_to_ms(stmin);
        ctx->frames_in_block = 0u;
        ctx->state           = ISOTP_TX_SENDING;

        /*
         * On antidate volontairement pour que la premiere Consecutive
         * Frame parte sans attendre STmin : l'ecart minimal s'applique
         * ENTRE deux CF, pas entre le Flow Control et la premiere.
         */
        ctx->last_frame_time_ms = (uint32_t)(now_ms - (uint32_t)ctx->stmin_ms);

        return isotp_tx_poll(ctx, now_ms, out);

    case ISOTP_FC_WAIT:
        /* Le recepteur demande du temps : on relance le compteur N_Bs. */
        ctx->wait_start_ms = now_ms;
        out->event = ISOTP_TX_EVENT_WAIT;
        return ISOTP_OK;

    case ISOTP_FC_OVERFLOW:
    default:
        /*
         * Le recepteur annonce qu'il ne peut pas stocker le message.
         * Insister serait inutile : on abandonne proprement.
         */
        tx_go_idle(ctx);
        out->event  = ISOTP_TX_EVENT_ABORTED;
        out->reason = ISOTP_ERR_ABORTED;
        return ISOTP_OK;
    }
}

/* ------------------------------------------------------------------ */
/* Progression                                                         */
/* ------------------------------------------------------------------ */

isotp_result_t isotp_tx_poll(isotp_tx_context_t *ctx,
                             uint32_t now_ms,
                             isotp_tx_result_t *out)
{
    if ((ctx == NULL) || (out == NULL))
    {
        return ISOTP_ERR_NULL_POINTER;
    }

    tx_result_clear(out);

    switch (ctx->state)
    {
    case ISOTP_TX_IDLE:
        out->event = ISOTP_TX_EVENT_NONE;
        return ISOTP_OK;

    case ISOTP_TX_WAIT_FLOW_CONTROL:
        /*
         * N_Bs : delai maximal d'attente du Flow Control. Sans lui, un
         * recepteur qui se tait apres la First Frame bloquerait
         * l'emetteur indefiniment.
         */
        if ((uint32_t)(now_ms - ctx->wait_start_ms) >= ISOTP_N_BS_TIMEOUT_MS)
        {
            ctx->stat_timeouts++;
            tx_go_idle(ctx);
            out->event  = ISOTP_TX_EVENT_ABORTED;
            out->reason = ISOTP_ERR_TIMEOUT;
        }
        else
        {
            out->event = ISOTP_TX_EVENT_WAIT;
        }
        return ISOTP_OK;

    case ISOTP_TX_SENDING:
        break;

    default:
        tx_go_idle(ctx);
        out->event  = ISOTP_TX_EVENT_ABORTED;
        out->reason = ISOTP_ERR_UNEXPECTED_FRAME;
        return ISOTP_OK;
    }

    /*
     * Bloc termine : le recepteur avait autorise block_size trames, il
     * faut redemander l'autorisation.
     */
    if ((ctx->block_size != 0u) &&
        (ctx->frames_in_block >= ctx->block_size))
    {
        ctx->state           = ISOTP_TX_WAIT_FLOW_CONTROL;
        ctx->wait_start_ms   = now_ms;
        ctx->frames_in_block = 0u;
        out->event = ISOTP_TX_EVENT_WAIT;
        return ISOTP_OK;
    }

    /* STmin : ecart minimal impose entre deux Consecutive Frames. */
    if ((uint32_t)(now_ms - ctx->last_frame_time_ms) <
        (uint32_t)ctx->stmin_ms)
    {
        out->event = ISOTP_TX_EVENT_WAIT;
        return ISOTP_OK;
    }

    build_consecutive_frame(ctx, out);
    ctx->last_frame_time_ms = now_ms;

    if (ctx->sent_length >= ctx->total_length)
    {
        /*
         * Derniere trame : l'appelant doit encore l'emettre, donc
         * l'evenement reste SEND_FRAME. La fin est signalee par le
         * retour a l'etat repos, visible au prochain appel.
         */
        ctx->stat_messages++;
        tx_go_idle(ctx);
    }

    return ISOTP_OK;
}
