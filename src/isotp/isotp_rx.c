/*
 * isotp_rx.c
 *
 * Reception ISO-TP : machine a etats de reassemblage.
 *
 * Une machine a etats, c'est trois choses : un ETAT courant, des
 * EVENEMENTS qui arrivent, et des TRANSITIONS qui disent quel etat
 * suit. Ici :
 *
 *   etats       : IDLE, WAIT_CONSECUTIVE
 *   evenements  : reception d'une SF, FF, CF, FC ; expiration de N_Cr
 *   transitions :
 *
 *      IDLE --- SF recue ------------> IDLE          (message complet)
 *      IDLE --- FF recue ------------> WAIT_CONSECUTIVE (emettre FC)
 *      IDLE --- CF recue ------------> IDLE          (ignoree)
 *
 *      WAIT_CONSECUTIVE --- CF attendue, message incomplet --> WAIT_CONSECUTIVE
 *      WAIT_CONSECUTIVE --- CF attendue, message complet ----> IDLE
 *      WAIT_CONSECUTIVE --- CF de mauvais numero ------------> IDLE (abandon)
 *      WAIT_CONSECUTIVE --- FF recue ------------------------> WAIT_CONSECUTIVE
 *                                                              (redemarrage)
 *      WAIT_CONSECUTIVE --- N_Cr expire ---------------------> IDLE (abandon)
 *
 * L'interet d'ecrire la machine explicitement plutot qu'en cascade de
 * if : chaque transition est visible, et un cas non prevu tombe dans un
 * defaut qui remet le contexte au repos au lieu de le laisser dans un
 * etat batard.
 *
 * Regle absolue : quelle que soit la trame recue, le contexte finit
 * dans un etat defini. Un attaquant ne doit pas pouvoir le figer.
 */

#include "isotp.h"

#define PCI_TYPE_SHIFT   4u
#define PCI_TYPE_MASK    0x0Fu
#define PCI_LOW_MASK     0x0Fu

#define FF_PCI_LEN       2u
#define CF_PCI_LEN       1u

/* Longueur du PCI d'une First Frame en forme etendue (FF_DL 32 bits). */
#define FF_ESCAPE_PCI_LEN 6u

/*
 * Parametres du Flow Control emis par ce recepteur.
 *
 * BlockSize 0 : on accepte toutes les Consecutive Frames sans redemander
 *               de Flow Control. Simple et suffisant sur un bus virtuel.
 * STmin 0     : aucun ecart minimal impose a l'emetteur.
 *
 * Ces valeurs sont volontairement permissives : le but du projet est de
 * durcir le PARSING, pas d'optimiser le debit.
 */
#define RX_FC_BLOCK_SIZE  0u
#define RX_FC_STMIN       0u

/* ------------------------------------------------------------------ */
/* Utilitaires internes                                                */
/* ------------------------------------------------------------------ */

static void result_clear(isotp_rx_result_t *out)
{
    uint8_t i;

    out->event       = ISOTP_RX_EVENT_NONE;
    out->message     = NULL;
    out->message_len = 0u;
    out->fc_len      = 0u;
    out->reason      = ISOTP_OK;

    for (i = 0u; i < ISOTP_CAN_FRAME_SIZE; i++)
    {
        out->fc_frame[i] = 0u;
    }
}

static void go_idle(isotp_rx_context_t *ctx)
{
    ctx->state                = ISOTP_RX_IDLE;
    ctx->expected_length      = 0u;
    ctx->received_length      = 0u;
    ctx->next_sequence_number = 0u;
}

/* Abandonne le transfert en cours et signale le motif. */
static void abort_transfer(isotp_rx_context_t *ctx,
                           isotp_rx_result_t *out,
                           isotp_result_t reason)
{
    go_idle(ctx);
    out->event  = ISOTP_RX_EVENT_ABORTED;
    out->reason = reason;
}

static void build_flow_control(isotp_rx_result_t *out,
                               isotp_flow_status_t status)
{
    (void)isotp_encode_flow_control(status,
                                    RX_FC_BLOCK_SIZE,
                                    RX_FC_STMIN,
                                    out->fc_frame,
                                    ISOTP_CAN_FRAME_SIZE,
                                    &out->fc_len);
    out->event = ISOTP_RX_EVENT_SEND_FLOW_CONTROL;
}

/* ------------------------------------------------------------------ */
/* Cycle de vie                                                        */
/* ------------------------------------------------------------------ */

void isotp_rx_init(isotp_rx_context_t *ctx)
{
    if (ctx == NULL)
    {
        return;
    }

    go_idle(ctx);
    ctx->last_frame_time_ms   = 0u;
    ctx->stat_frames          = 0u;
    ctx->stat_messages        = 0u;
    ctx->stat_rejected        = 0u;
    ctx->stat_sequence_errors = 0u;
    ctx->stat_overflows       = 0u;
    ctx->stat_timeouts        = 0u;
}

void isotp_rx_reset(isotp_rx_context_t *ctx)
{
    if (ctx != NULL)
    {
        go_idle(ctx);
    }
}

/* ------------------------------------------------------------------ */
/* Traitement d'une Single Frame                                       */
/* ------------------------------------------------------------------ */

static void handle_single_frame(isotp_rx_context_t *ctx,
                                const uint8_t *frame,
                                uint8_t frame_len,
                                isotp_rx_result_t *out)
{
    const uint8_t *payload = NULL;
    uint8_t payload_len = 0u;
    isotp_result_t res;
    uint8_t i;

    res = isotp_decode_single_frame(frame, frame_len, &payload, &payload_len);

    if (res != ISOTP_OK)
    {
        ctx->stat_rejected++;
        /*
         * Une SF malformee n'interrompt pas un transfert multi-trames
         * en cours : elle est simplement ignoree. Autoriser une trame
         * invalide a detruire un transfert valide serait un vecteur de
         * deni de service.
         */
        out->event  = ISOTP_RX_EVENT_NONE;
        out->reason = res;
        return;
    }

    /*
     * Une Single Frame valide arrivant pendant un transfert multi-trames
     * remplace ce transfert. La norme laisse le choix ; on privilegie le
     * message complet et coherent qui vient d'arriver.
     */
    if (ctx->state != ISOTP_RX_IDLE)
    {
        go_idle(ctx);
    }

    for (i = 0u; i < payload_len; i++)
    {
        ctx->buffer[i] = payload[i];
    }

    ctx->received_length = payload_len;
    ctx->expected_length = payload_len;

    ctx->stat_messages++;

    out->event       = ISOTP_RX_EVENT_MESSAGE_READY;
    out->message     = ctx->buffer;
    out->message_len = payload_len;
}

/* ------------------------------------------------------------------ */
/* Traitement d'une First Frame                                        */
/* ------------------------------------------------------------------ */

static void handle_first_frame(isotp_rx_context_t *ctx,
                               const uint8_t *frame,
                               uint8_t frame_len,
                               isotp_rx_result_t *out)
{
    uint32_t ff_dl;
    uint8_t  header_len;
    uint8_t  copy_len;
    uint8_t  i;

    /* Il faut au moins les 2 octets de PCI. */
    if (frame_len < FF_PCI_LEN)
    {
        ctx->stat_rejected++;
        out->event  = ISOTP_RX_EVENT_NONE;
        out->reason = ISOTP_ERR_TRUNCATED_FRAME;
        return;
    }

    /*
     * FF_DL sur 12 bits : 4 bits bas du premier octet, puis le second
     * octet entier.
     *
     *   octet0 = 0x1X  ->  X = bits 11..8
     *   octet1         ->  bits 7..0
     *
     * Exemple : 10 14  ->  0x014 = 20 octets annonces.
     */
    ff_dl = (uint32_t)(((uint32_t)(frame[0] & PCI_LOW_MASK) << 8) |
                       (uint32_t)frame[1]);

    header_len = FF_PCI_LEN;

    if (ff_dl == 0u)
    {
        /*
         * Forme etendue : FF_DL nul sur 12 bits signale une longueur
         * codee sur les 4 octets suivants. Elle sert aux messages de
         * plus de 4095 octets.
         */
        if (frame_len < FF_ESCAPE_PCI_LEN)
        {
            ctx->stat_rejected++;
            out->event  = ISOTP_RX_EVENT_NONE;
            out->reason = ISOTP_ERR_TRUNCATED_FRAME;
            return;
        }

        ff_dl = (((uint32_t)frame[2]) << 24) |
                (((uint32_t)frame[3]) << 16) |
                (((uint32_t)frame[4]) << 8)  |
                ((uint32_t)frame[5]);

        header_len = FF_ESCAPE_PCI_LEN;
    }

    /*
     * Un message de 7 octets ou moins doit voyager en Single Frame.
     * Une First Frame qui en annonce moins est malformee.
     */
    if (ff_dl < ISOTP_FF_MIN_LENGTH)
    {
        ctx->stat_rejected++;
        out->event  = ISOTP_RX_EVENT_NONE;
        out->reason = ISOTP_ERR_INVALID_LENGTH;
        return;
    }

    /*
     * Le message annonce depasse ce que l'on sait stocker. La norme
     * prevoit exactement ce cas : on repond par un Flow Control portant
     * FlowStatus = Overflow, et on ne reserve rien. C'est la difference
     * entre refuser proprement et se faire deborder.
     */
    if (ff_dl > (uint32_t)ISOTP_MAX_PAYLOAD_SIZE)
    {
        ctx->stat_overflows++;
        go_idle(ctx);
        build_flow_control(out, ISOTP_FC_OVERFLOW);
        out->reason = ISOTP_ERR_OVERFLOW;
        return;
    }

    /* Nombre d'octets utiles reellement presents dans cette trame. */
    if (frame_len <= header_len)
    {
        ctx->stat_rejected++;
        out->event  = ISOTP_RX_EVENT_NONE;
        out->reason = ISOTP_ERR_TRUNCATED_FRAME;
        return;
    }

    copy_len = (uint8_t)(frame_len - header_len);

    /* Ne jamais copier plus que ce que le message annonce. */
    if ((uint32_t)copy_len > ff_dl)
    {
        copy_len = (uint8_t)ff_dl;
    }

    for (i = 0u; i < copy_len; i++)
    {
        ctx->buffer[i] = frame[header_len + i];
    }

    ctx->state                = ISOTP_RX_WAIT_CONSECUTIVE;
    ctx->expected_length      = (uint16_t)ff_dl;
    ctx->received_length      = copy_len;
    ctx->next_sequence_number = 1u;   /* la FF compte comme la sequence 0 */

    build_flow_control(out, ISOTP_FC_CONTINUE_TO_SEND);
}

/* ------------------------------------------------------------------ */
/* Traitement d'une Consecutive Frame                                  */
/* ------------------------------------------------------------------ */

static void handle_consecutive_frame(isotp_rx_context_t *ctx,
                                     const uint8_t *frame,
                                     uint8_t frame_len,
                                     isotp_rx_result_t *out)
{
    uint8_t  sequence_number;
    uint16_t remaining;
    uint8_t  available;
    uint8_t  copy_len;
    uint8_t  i;

    /*
     * Une Consecutive Frame hors transfert n'a aucun sens. On l'ignore
     * sans changer d'etat : c'est le cas d'un fuzzer qui envoie des CF
     * isolees.
     */
    if (ctx->state != ISOTP_RX_WAIT_CONSECUTIVE)
    {
        ctx->stat_rejected++;
        out->event  = ISOTP_RX_EVENT_NONE;
        out->reason = ISOTP_ERR_UNEXPECTED_FRAME;
        return;
    }

    if (frame_len < (CF_PCI_LEN + 1u))
    {
        ctx->stat_rejected++;
        out->event  = ISOTP_RX_EVENT_NONE;
        out->reason = ISOTP_ERR_TRUNCATED_FRAME;
        return;
    }

    sequence_number = (uint8_t)(frame[0] & PCI_LOW_MASK);

    /*
     * Le numero de sequence est code sur 4 bits : il compte de 1 a 15
     * puis repasse a 0. Un ecart, meme d'une unite, signale une trame
     * perdue, dupliquee ou injectee : le transfert est abandonne.
     *
     * C'est le scenario d'attaque principal du fuzzer : 21 22 27 au
     * lieu de 21 22 23.
     */
    if (sequence_number != ctx->next_sequence_number)
    {
        ctx->stat_sequence_errors++;
        abort_transfer(ctx, out, ISOTP_ERR_SEQUENCE_NUMBER);
        return;
    }

    remaining = (uint16_t)(ctx->expected_length - ctx->received_length);
    available = (uint8_t)(frame_len - CF_PCI_LEN);

    /*
     * On copie le minimum entre ce qui reste a recevoir et ce que la
     * trame contient reellement. Les deux bornes comptent : la premiere
     * evite de deborder le message, la seconde d'inventer des octets.
     */
    copy_len = available;
    if ((uint16_t)copy_len > remaining)
    {
        copy_len = (uint8_t)remaining;
    }

    /*
     * Verification de capacite avant ecriture. expected_length a deja
     * ete valide contre ISOTP_MAX_PAYLOAD_SIZE a la First Frame, mais
     * on ne s'appuie pas sur une garantie prise ailleurs.
     */
    if (((uint32_t)ctx->received_length + (uint32_t)copy_len) >
        (uint32_t)ISOTP_MAX_PAYLOAD_SIZE)
    {
        ctx->stat_overflows++;
        abort_transfer(ctx, out, ISOTP_ERR_OVERFLOW);
        return;
    }

    for (i = 0u; i < copy_len; i++)
    {
        ctx->buffer[ctx->received_length + i] = frame[CF_PCI_LEN + i];
    }

    ctx->received_length = (uint16_t)(ctx->received_length + copy_len);

    /* Sequence suivante, modulo 16. */
    ctx->next_sequence_number =
        (uint8_t)((ctx->next_sequence_number + 1u) & PCI_LOW_MASK);

    if (ctx->received_length >= ctx->expected_length)
    {
        ctx->stat_messages++;

        out->event       = ISOTP_RX_EVENT_MESSAGE_READY;
        out->message     = ctx->buffer;
        out->message_len = ctx->expected_length;

        go_idle(ctx);
        return;
    }

    out->event = ISOTP_RX_EVENT_NONE;
}

/* ------------------------------------------------------------------ */
/* Point d'entree                                                      */
/* ------------------------------------------------------------------ */

isotp_result_t isotp_rx_process(isotp_rx_context_t *ctx,
                                const uint8_t *frame,
                                uint8_t frame_len,
                                uint32_t now_ms,
                                isotp_rx_result_t *out)
{
    isotp_frame_type_t type;

    if ((ctx == NULL) || (frame == NULL) || (out == NULL))
    {
        return ISOTP_ERR_NULL_POINTER;
    }

    result_clear(out);

    if (frame_len < 1u)
    {
        ctx->stat_rejected++;
        out->reason = ISOTP_ERR_INVALID_LENGTH;
        return ISOTP_OK;
    }

    ctx->stat_frames++;
    ctx->last_frame_time_ms = now_ms;

    type = (isotp_frame_type_t)((frame[0] >> PCI_TYPE_SHIFT) & PCI_TYPE_MASK);

    switch (type)
    {
    case ISOTP_FRAME_SINGLE:
        handle_single_frame(ctx, frame, frame_len, out);
        break;

    case ISOTP_FRAME_FIRST:
        handle_first_frame(ctx, frame, frame_len, out);
        break;

    case ISOTP_FRAME_CONSECUTIVE:
        handle_consecutive_frame(ctx, frame, frame_len, out);
        break;

    /*
     * Un Flow Control concerne l'emetteur, pas le recepteur. Le voir
     * ici signifie qu'il ne nous etait pas destine : on l'ignore sans
     * toucher a l'etat.
     */
    case ISOTP_FRAME_FLOW_CONTROL:
        ctx->stat_rejected++;
        out->reason = ISOTP_ERR_UNEXPECTED_FRAME;
        break;

    /*
     * Types 4 a 15 : inexistants dans la norme. Un fuzzer en produira.
     * On les rejette sans interrompre un transfert legitime.
     */
    default:
        ctx->stat_rejected++;
        out->reason = ISOTP_ERR_UNEXPECTED_FRAME;
        break;
    }

    return ISOTP_OK;
}

isotp_result_t isotp_rx_poll_timeout(isotp_rx_context_t *ctx,
                                     uint32_t now_ms,
                                     isotp_rx_result_t *out)
{
    if ((ctx == NULL) || (out == NULL))
    {
        return ISOTP_ERR_NULL_POINTER;
    }

    result_clear(out);

    if (ctx->state != ISOTP_RX_WAIT_CONSECUTIVE)
    {
        return ISOTP_OK;
    }

    /*
     * Soustraction en arithmetique non signee : elle reste correcte
     * meme quand l'horloge repasse par zero apres 49 jours, car le
     * resultat modulo 2^32 donne toujours l'ecart reel tant que celui-ci
     * est inferieur a la periode.
     */
    if ((uint32_t)(now_ms - ctx->last_frame_time_ms) >= ISOTP_N_CR_TIMEOUT_MS)
    {
        ctx->stat_timeouts++;
        abort_transfer(ctx, out, ISOTP_ERR_TIMEOUT);
    }

    return ISOTP_OK;
}
