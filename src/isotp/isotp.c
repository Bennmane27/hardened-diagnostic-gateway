/*
 * isotp.c
 *
 * ISO-TP : encodage et decodage des trames isolees.
 *
 * Le reassemblage vit dans isotp_rx.c, la segmentation dans isotp_tx.c.
 *
 * Aucun header systeme : cette couche doit rester portable.
 */

#include "isotp.h"

/*
 * Structure du premier octet ISO-TP, le PCI.
 *
 * Single Frame :
 *   bit  7 6 5 4 | 3 2 1 0
 *        type=0  | SF_DL
 *
 * First Frame :
 *   octet 0 : type=1 | FF_DL bits 11..8
 *   octet 1 :          FF_DL bits 7..0
 *
 * Consecutive Frame :
 *   bit  7 6 5 4 | 3 2 1 0
 *        type=2  | numero de sequence
 *
 * Flow Control :
 *   octet 0 : type=3 | FlowStatus
 *   octet 1 : BlockSize
 *   octet 2 : STmin
 *
 * Exemple, 0x02 :
 *   0000 0010
 *   ^^^^        type  = 0 -> Single Frame
 *        ^^^^   SF_DL = 2 -> 2 octets utiles
 */
#define PCI_TYPE_SHIFT   4u
#define PCI_TYPE_MASK    0x0Fu
#define PCI_LOW_MASK     0x0Fu

#define SF_PCI_LEN       1u
#define FF_PCI_LEN       2u
#define CF_PCI_LEN       1u
#define FC_PCI_LEN       3u

const char *isotp_result_to_string(isotp_result_t result)
{
    switch (result)
    {
    case ISOTP_OK:                   return "OK";
    case ISOTP_ERR_NULL_POINTER:     return "null pointer";
    case ISOTP_ERR_BUFFER_TOO_SMALL: return "buffer too small";
    case ISOTP_ERR_INVALID_LENGTH:   return "invalid length";
    case ISOTP_ERR_NOT_SINGLE_FRAME: return "unexpected frame type";
    case ISOTP_ERR_TRUNCATED_FRAME:  return "truncated frame — it announces more payload than it carries";
    case ISOTP_ERR_UNEXPECTED_FRAME: return "frame unexpected in this state";
    case ISOTP_ERR_SEQUENCE_NUMBER:  return "wrong sequence number";
    case ISOTP_ERR_OVERFLOW:         return "message larger than the reassembly buffer";
    case ISOTP_ERR_TIMEOUT:          return "deadline expired";
    case ISOTP_ERR_ABORTED:          return "transfer aborted by the peer";
    case ISOTP_ERR_BUSY:             return "a transfer is already in progress";
    default:                         return "unknown error";
    }
}

const char *isotp_frame_type_to_string(isotp_frame_type_t type)
{
    switch (type)
    {
    case ISOTP_FRAME_SINGLE:       return "Single Frame";
    case ISOTP_FRAME_FIRST:        return "First Frame";
    case ISOTP_FRAME_CONSECUTIVE:  return "Consecutive Frame";
    case ISOTP_FRAME_FLOW_CONTROL: return "Flow Control";
    default:                       return "unknown frame type";
    }
}

/* ------------------------------------------------------------------ */
/* Type de trame                                                       */
/* ------------------------------------------------------------------ */

isotp_result_t isotp_get_frame_type(const uint8_t *frame,
                                    uint8_t frame_len,
                                    isotp_frame_type_t *out_type)
{
    if ((frame == NULL) || (out_type == NULL))
    {
        return ISOTP_ERR_NULL_POINTER;
    }

    if (frame_len < 1u)
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    *out_type = (isotp_frame_type_t)((frame[0] >> PCI_TYPE_SHIFT) &
                                     PCI_TYPE_MASK);
    return ISOTP_OK;
}

/* ------------------------------------------------------------------ */
/* Single Frame                                                        */
/* ------------------------------------------------------------------ */

isotp_result_t isotp_encode_single_frame(const uint8_t *payload,
                                         uint8_t payload_len,
                                         uint8_t *frame,
                                         uint8_t frame_capacity,
                                         uint8_t *out_frame_len)
{
    uint8_t i;

    if ((payload == NULL) || (frame == NULL) || (out_frame_len == NULL))
    {
        return ISOTP_ERR_NULL_POINTER;
    }

    /*
     * SF_DL nul est interdit : une Single Frame transporte au moins un
     * octet. Au-dela de 7, il faut une First Frame.
     */
    if ((payload_len == 0u) || (payload_len > ISOTP_SF_MAX_PAYLOAD))
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    if (frame_capacity < ISOTP_CAN_FRAME_SIZE)
    {
        return ISOTP_ERR_BUFFER_TOO_SMALL;
    }

    frame[0] = (uint8_t)(((uint8_t)ISOTP_FRAME_SINGLE << PCI_TYPE_SHIFT) |
                         (payload_len & PCI_LOW_MASK));

    for (i = 0u; i < payload_len; i++)
    {
        frame[SF_PCI_LEN + i] = payload[i];
    }
    for (i = (uint8_t)(SF_PCI_LEN + payload_len);
         i < ISOTP_CAN_FRAME_SIZE; i++)
    {
        frame[i] = ISOTP_PADDING_BYTE;
    }

    *out_frame_len = ISOTP_CAN_FRAME_SIZE;
    return ISOTP_OK;
}

isotp_result_t isotp_decode_single_frame(const uint8_t *frame,
                                         uint8_t frame_len,
                                         const uint8_t **out_payload,
                                         uint8_t *out_payload_len)
{
    uint8_t frame_type;
    uint8_t sf_dl;

    if ((frame == NULL) || (out_payload == NULL) || (out_payload_len == NULL))
    {
        return ISOTP_ERR_NULL_POINTER;
    }

    if (frame_len < SF_PCI_LEN)
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    frame_type = (uint8_t)((frame[0] >> PCI_TYPE_SHIFT) & PCI_TYPE_MASK);
    if (frame_type != (uint8_t)ISOTP_FRAME_SINGLE)
    {
        return ISOTP_ERR_NOT_SINGLE_FRAME;
    }

    sf_dl = (uint8_t)(frame[0] & PCI_LOW_MASK);

    if ((sf_dl == 0u) || (sf_dl > ISOTP_SF_MAX_PAYLOAD))
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    /*
     * Controle anti-troncature : une trame peut annoncer 7 octets
     * utiles tout en n'ayant ete recue qu'avec un DLC de 3. On refuse
     * au lieu de lire des octets inexistants.
     */
    if ((uint8_t)(SF_PCI_LEN + sf_dl) > frame_len)
    {
        return ISOTP_ERR_TRUNCATED_FRAME;
    }

    *out_payload = &frame[SF_PCI_LEN];
    *out_payload_len = sf_dl;
    return ISOTP_OK;
}

/* ------------------------------------------------------------------ */
/* Flow Control                                                        */
/* ------------------------------------------------------------------ */

isotp_result_t isotp_encode_flow_control(isotp_flow_status_t status,
                                         uint8_t block_size,
                                         uint8_t stmin,
                                         uint8_t *frame,
                                         uint8_t frame_capacity,
                                         uint8_t *out_frame_len)
{
    uint8_t i;

    if ((frame == NULL) || (out_frame_len == NULL))
    {
        return ISOTP_ERR_NULL_POINTER;
    }

    if (frame_capacity < ISOTP_CAN_FRAME_SIZE)
    {
        return ISOTP_ERR_BUFFER_TOO_SMALL;
    }

    if (((uint8_t)status & ~PCI_LOW_MASK) != 0u)
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    frame[0] = (uint8_t)(((uint8_t)ISOTP_FRAME_FLOW_CONTROL << PCI_TYPE_SHIFT) |
                         ((uint8_t)status & PCI_LOW_MASK));
    frame[1] = block_size;
    frame[2] = stmin;

    for (i = FC_PCI_LEN; i < ISOTP_CAN_FRAME_SIZE; i++)
    {
        frame[i] = ISOTP_PADDING_BYTE;
    }

    *out_frame_len = ISOTP_CAN_FRAME_SIZE;
    return ISOTP_OK;
}

isotp_result_t isotp_decode_flow_control(const uint8_t *frame,
                                         uint8_t frame_len,
                                         isotp_flow_status_t *out_status,
                                         uint8_t *out_block_size,
                                         uint8_t *out_stmin)
{
    uint8_t frame_type;
    uint8_t status;

    if ((frame == NULL) || (out_status == NULL) ||
        (out_block_size == NULL) || (out_stmin == NULL))
    {
        return ISOTP_ERR_NULL_POINTER;
    }

    /*
     * Un Flow Control occupe 3 octets utiles. Une trame plus courte est
     * inexploitable : BlockSize ou STmin manqueraient.
     */
    if (frame_len < FC_PCI_LEN)
    {
        return ISOTP_ERR_TRUNCATED_FRAME;
    }

    frame_type = (uint8_t)((frame[0] >> PCI_TYPE_SHIFT) & PCI_TYPE_MASK);
    if (frame_type != (uint8_t)ISOTP_FRAME_FLOW_CONTROL)
    {
        return ISOTP_ERR_UNEXPECTED_FRAME;
    }

    status = (uint8_t)(frame[0] & PCI_LOW_MASK);

    /* 0x3 a 0xF sont reserves : on refuse plutot que d'interpreter. */
    if (status > (uint8_t)ISOTP_FC_OVERFLOW)
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    *out_status     = (isotp_flow_status_t)status;
    *out_block_size = frame[1];
    *out_stmin      = frame[2];

    return ISOTP_OK;
}

uint8_t isotp_stmin_to_ms(uint8_t stmin)
{
    /* 0x00 a 0x7F : valeur directe en millisecondes. */
    if (stmin <= 0x7Fu)
    {
        return stmin;
    }

    /*
     * 0xF1 a 0xF9 : 100 a 900 microsecondes. Sous Linux on ne pretend
     * pas a cette granularite ; on arrondit a 1 ms, ce qui est plus lent
     * donc toujours conforme du point de vue du recepteur.
     */
    if ((stmin >= 0xF1u) && (stmin <= 0xF9u))
    {
        return 1u;
    }

    /*
     * Valeurs reservees. La norme demande de les traiter comme la
     * valeur la plus prudente : on prend le maximum, 127 ms.
     */
    return 0x7Fu;
}
