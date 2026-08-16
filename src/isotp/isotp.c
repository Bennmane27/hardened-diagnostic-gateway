/*
 * isotp.c
 *
 * Implementation ISO-TP partielle : Single Frame.
 *
 * Aucun header systeme / Linux ici : cette couche doit rester portable.
 */

#include "isotp.h"

/*
 * Masques et decalages du premier octet ISO-TP (le PCI).
 *
 * Structure du PCI pour une Single Frame en CAN classique :
 *
 *   bit  7 6 5 4 | 3 2 1 0
 *        type    | SF_DL
 *
 * Exemple : 0x02
 *   0000 0010
 *   ^^^^        type  = 0 -> Single Frame
 *        ^^^^   SF_DL = 2 -> 2 octets de payload
 */
#define ISOTP_PCI_TYPE_SHIFT   4u
#define ISOTP_PCI_TYPE_MASK    0x0Fu
#define ISOTP_PCI_SF_DL_MASK   0x0Fu

/* Longueur du PCI d'une Single Frame, en octets. */
#define ISOTP_SF_PCI_LEN       1u

const char *isotp_result_to_string(isotp_result_t result)
{
    switch (result)
    {
    case ISOTP_OK:
        return "OK";

    case ISOTP_ERR_NULL_POINTER:
        return "pointeur NULL";

    case ISOTP_ERR_BUFFER_TOO_SMALL:
        return "tampon trop petit";

    case ISOTP_ERR_INVALID_LENGTH:
        return "longueur invalide";

    case ISOTP_ERR_NOT_SINGLE_FRAME:
        return "type de trame non supporte";

    case ISOTP_ERR_TRUNCATED_FRAME:
        return "trame tronquee (longueur annoncee > longueur recue)";

    default:
        return "erreur inconnue";
    }
}

isotp_result_t isotp_get_frame_type(const uint8_t *frame,
                                    uint8_t frame_len,
                                    isotp_frame_type_t *out_type)
{
    uint8_t pci;

    if ((frame == NULL) || (out_type == NULL))
    {
        return ISOTP_ERR_NULL_POINTER;
    }

    /* Sans au moins un octet, il n'y a pas de PCI a lire. */
    if (frame_len < ISOTP_SF_PCI_LEN)
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    pci = frame[0];

    *out_type = (isotp_frame_type_t)((pci >> ISOTP_PCI_TYPE_SHIFT) &
                                     ISOTP_PCI_TYPE_MASK);

    return ISOTP_OK;
}

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
     * SF_DL == 0 est interdit par ISO 15765-2 : une Single Frame
     * transporte forcement au moins un octet utile.
     * Au-dela de 7 octets, il faudrait une First Frame.
     */
    if ((payload_len == 0u) || (payload_len > ISOTP_SF_MAX_PAYLOAD))
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    if (frame_capacity < ISOTP_CAN_FRAME_SIZE)
    {
        return ISOTP_ERR_BUFFER_TOO_SMALL;
    }

    /*
     * PCI : type Single Frame (0) sur les bits 7..4,
     *       longueur utile sur les bits 3..0.
     *
     * Le type valant 0, "0 << 4" ne change rien, mais on ecrit
     * l'expression complete pour que la structure reste explicite.
     */
    frame[0] = (uint8_t)(((uint8_t)ISOTP_FRAME_SINGLE << ISOTP_PCI_TYPE_SHIFT) |
                         (payload_len & ISOTP_PCI_SF_DL_MASK));

    for (i = 0u; i < payload_len; i++)
    {
        frame[ISOTP_SF_PCI_LEN + i] = payload[i];
    }

    /* Bourrage jusqu'a 8 octets. */
    for (i = (uint8_t)(ISOTP_SF_PCI_LEN + payload_len);
         i < ISOTP_CAN_FRAME_SIZE;
         i++)
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
    uint8_t pci;
    uint8_t frame_type;
    uint8_t sf_dl;

    if ((frame == NULL) || (out_payload == NULL) || (out_payload_len == NULL))
    {
        return ISOTP_ERR_NULL_POINTER;
    }

    if (frame_len < ISOTP_SF_PCI_LEN)
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    pci = frame[0];

    frame_type = (uint8_t)((pci >> ISOTP_PCI_TYPE_SHIFT) & ISOTP_PCI_TYPE_MASK);

    if (frame_type != (uint8_t)ISOTP_FRAME_SINGLE)
    {
        return ISOTP_ERR_NOT_SINGLE_FRAME;
    }

    sf_dl = (uint8_t)(pci & ISOTP_PCI_SF_DL_MASK);

    /*
     * SF_DL tient sur 4 bits, donc 0..15.
     * En CAN classique, seules les valeurs 1..7 ont un sens.
     * 0 est interdit ; 8..15 sont impossibles dans une trame de 8 octets.
     */
    if ((sf_dl == 0u) || (sf_dl > ISOTP_SF_MAX_PAYLOAD))
    {
        return ISOTP_ERR_INVALID_LENGTH;
    }

    /*
     * Verification anti-troncature.
     *
     * C'est le controle qui manquait dans l'ancien code : une trame
     * peut annoncer 7 octets utiles tout en n'ayant ete recue qu'avec
     * un DLC de 3. On refuse au lieu de lire des octets inexistants.
     */
    if ((uint8_t)(ISOTP_SF_PCI_LEN + sf_dl) > frame_len)
    {
        return ISOTP_ERR_TRUNCATED_FRAME;
    }

    *out_payload = &frame[ISOTP_SF_PCI_LEN];
    *out_payload_len = sf_dl;

    return ISOTP_OK;
}
