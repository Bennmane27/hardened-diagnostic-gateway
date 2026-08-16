/*
 * isotp.h
 *
 * Couche transport ISO-TP (ISO 15765-2), implementation partielle.
 *
 * Etat actuel : Single Frame uniquement (CAN classique, 8 octets).
 *
 * Cette couche est volontairement INDEPENDANTE de SocketCAN.
 * Elle ne manipule que des tampons d'octets bruts, jamais de
 * struct can_frame. C'est ce qui permettra plus tard de la porter
 * sur une autre plateforme (STM32 FDCAN par exemple) sans la reecrire.
 *
 * Contraintes :
 *  - aucune allocation dynamique
 *  - aucune variable globale
 *  - toutes les operations sont bornees (O(1) ou O(n) avec n <= 7)
 */

#ifndef ISOTP_H
#define ISOTP_H

#include <stdint.h>
#include <stddef.h>   /* NULL */

/* Taille d'une trame CAN classique. */
#define ISOTP_CAN_FRAME_SIZE   8u

/*
 * Une Single Frame utilise 1 octet de PCI (Protocol Control Information),
 * il reste donc au maximum 7 octets de donnees utiles.
 */
#define ISOTP_SF_MAX_PAYLOAD   7u

/*
 * Octet de bourrage utilise quand la payload fait moins de 7 octets.
 * ISO 15765-2 ne l'impose pas ; l'industrie utilise souvent 0xCC ou 0xAA.
 * On garde 0x00 pour rester identique au comportement actuel du projet.
 */
#define ISOTP_PADDING_BYTE     0x00u

/*
 * Types de trames ISO-TP.
 * Valeur codee sur les bits 7..4 du premier octet de la trame CAN.
 */
typedef enum
{
    ISOTP_FRAME_SINGLE       = 0x0,  /* SF : message tenant dans une trame */
    ISOTP_FRAME_FIRST        = 0x1,  /* FF : premiere trame d'un message long */
    ISOTP_FRAME_CONSECUTIVE  = 0x2,  /* CF : suite d'un message long */
    ISOTP_FRAME_FLOW_CONTROL = 0x3   /* FC : controle de flux du recepteur */
} isotp_frame_type_t;

/*
 * Codes de retour.
 *
 * Toutes les fonctions publiques renvoient un isotp_result_t.
 * ISOTP_OK == 0, donc "if (res != ISOTP_OK)" est le test d'erreur.
 */
typedef enum
{
    ISOTP_OK = 0,

    ISOTP_ERR_NULL_POINTER,      /* un argument obligatoire vaut NULL */
    ISOTP_ERR_BUFFER_TOO_SMALL,  /* tampon de sortie trop petit */
    ISOTP_ERR_INVALID_LENGTH,    /* longueur annoncee impossible */
    ISOTP_ERR_NOT_SINGLE_FRAME,  /* type de trame non gere pour l'instant */
    ISOTP_ERR_TRUNCATED_FRAME    /* la trame est plus courte que ce qu'elle annonce */
} isotp_result_t;

/*
 * Renvoie une chaine constante decrivant un code de retour.
 * Utile pour les traces ; ne fait aucune allocation.
 */
const char *isotp_result_to_string(isotp_result_t result);

/*
 * Lit le type d'une trame ISO-TP sans la decoder.
 *
 * frame      : octets de la trame CAN recue
 * frame_len  : nombre d'octets reellement recus (le DLC)
 * out_type   : recoit le type de trame
 *
 * Retour :
 *   ISOTP_OK
 *   ISOTP_ERR_NULL_POINTER
 *   ISOTP_ERR_INVALID_LENGTH  (frame_len == 0 : pas meme un octet de PCI)
 */
isotp_result_t isotp_get_frame_type(const uint8_t *frame,
                                    uint8_t frame_len,
                                    isotp_frame_type_t *out_type);

/*
 * Construit une Single Frame ISO-TP.
 *
 * payload         : donnees utiles (couche superieure, ex : UDS)
 * payload_len     : 1 a 7 octets
 * frame           : tampon de sortie fourni par l'appelant
 * frame_capacity  : taille de ce tampon
 * out_frame_len   : recoit le nombre d'octets a emettre (toujours 8 ici,
 *                   car on bourre la trame)
 *
 * Retour :
 *   ISOTP_OK
 *   ISOTP_ERR_NULL_POINTER
 *   ISOTP_ERR_INVALID_LENGTH    (payload_len == 0 ou > 7)
 *   ISOTP_ERR_BUFFER_TOO_SMALL  (frame_capacity < 8)
 */
isotp_result_t isotp_encode_single_frame(const uint8_t *payload,
                                         uint8_t payload_len,
                                         uint8_t *frame,
                                         uint8_t frame_capacity,
                                         uint8_t *out_frame_len);

/*
 * Decode une Single Frame ISO-TP.
 *
 * Aucune copie n'est effectuee : out_payload recoit un pointeur
 * a l'interieur de frame. Le tampon frame doit donc rester valide
 * tant que l'appelant utilise la payload.
 *
 * frame            : octets de la trame CAN recue
 * frame_len        : nombre d'octets reellement recus (le DLC)
 * out_payload      : recoit un pointeur vers le premier octet utile
 * out_payload_len  : recoit la longueur utile annoncee et validee
 *
 * Retour :
 *   ISOTP_OK
 *   ISOTP_ERR_NULL_POINTER
 *   ISOTP_ERR_INVALID_LENGTH     (frame_len == 0, ou SF_DL == 0, ou SF_DL > 7)
 *   ISOTP_ERR_NOT_SINGLE_FRAME   (bits 7..4 != 0)
 *   ISOTP_ERR_TRUNCATED_FRAME    (1 + SF_DL > frame_len)
 */
isotp_result_t isotp_decode_single_frame(const uint8_t *frame,
                                         uint8_t frame_len,
                                         const uint8_t **out_payload,
                                         uint8_t *out_payload_len);

#endif /* ISOTP_H */
