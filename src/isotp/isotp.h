/*
 * isotp.h
 *
 * Couche transport ISO-TP (ISO 15765-2), CAN classique.
 *
 * Prend en charge :
 *   SF  Single Frame
 *   FF  First Frame
 *   CF  Consecutive Frame
 *   FC  Flow Control
 *   reassemblage, numeros de sequence, temporisations N_Bs et N_Cr
 *
 * Cette couche est INDEPENDANTE de SocketCAN et de Linux. Elle ne
 * manipule que des tampons d'octets et ne connait pas l'heure : le
 * temps lui est fourni par l'appelant sous forme de millisecondes
 * monotones. C'est ce qui permet de la porter sur microcontroleur et de
 * tester les temporisations sans attendre reellement.
 *
 * Contraintes : aucune allocation dynamique, aucun etat global, toutes
 * les operations sont bornees.
 */

#ifndef ISOTP_H
#define ISOTP_H

#include <stdint.h>
#include <stddef.h>   /* NULL */

/* ------------------------------------------------------------------ */
/* Constantes de format                                                */
/* ------------------------------------------------------------------ */

/* Taille d'une trame CAN classique. */
#define ISOTP_CAN_FRAME_SIZE   8u

/* Une Single Frame reserve 1 octet au PCI : 7 octets utiles au plus. */
#define ISOTP_SF_MAX_PAYLOAD   7u

/* Une First Frame reserve 2 octets au PCI : 6 octets utiles. */
#define ISOTP_FF_FIRST_PAYLOAD 6u

/* Une Consecutive Frame reserve 1 octet au PCI : 7 octets utiles. */
#define ISOTP_CF_MAX_PAYLOAD   7u

/*
 * Un message de 7 octets ou moins doit passer en Single Frame. Une
 * First Frame annoncant moins de 8 octets est donc malformee.
 */
#define ISOTP_FF_MIN_LENGTH    8u

/*
 * Taille maximale d'un message reassemble.
 *
 * 4095 est la limite de l'adressage classique : FF_DL tient sur 12
 * bits. Redefinissable a la compilation (-DISOTP_MAX_PAYLOAD_SIZE=...)
 * pour une cible a memoire contrainte.
 */
#ifndef ISOTP_MAX_PAYLOAD_SIZE
#define ISOTP_MAX_PAYLOAD_SIZE 4095u
#endif

/*
 * Octet de bourrage. ISO 15765-2 ne l'impose pas ; 0x00 est conserve
 * pour rester coherent avec l'historique du projet.
 */
#define ISOTP_PADDING_BYTE     0x00u

/* ------------------------------------------------------------------ */
/* Temporisations                                                      */
/*                                                                     */
/* N_Bs : cote emetteur, delai maximal d'attente d'un Flow Control.    */
/* N_Cr : cote recepteur, delai maximal entre deux Consecutive Frames. */
/*                                                                     */
/* Les valeurs par defaut de la norme sont de 1000 ms.                 */
/* ------------------------------------------------------------------ */

#ifndef ISOTP_N_BS_TIMEOUT_MS
#define ISOTP_N_BS_TIMEOUT_MS  1000u
#endif

#ifndef ISOTP_N_CR_TIMEOUT_MS
#define ISOTP_N_CR_TIMEOUT_MS  1000u
#endif

/* ------------------------------------------------------------------ */
/* Types de trames                                                     */
/* ------------------------------------------------------------------ */

typedef enum
{
    ISOTP_FRAME_SINGLE       = 0x0,
    ISOTP_FRAME_FIRST        = 0x1,
    ISOTP_FRAME_CONSECUTIVE  = 0x2,
    ISOTP_FRAME_FLOW_CONTROL = 0x3
} isotp_frame_type_t;

/*
 * FlowStatus, champ bas du premier octet d'une trame Flow Control.
 *
 * CONTINUE_TO_SEND : l'emetteur peut poursuivre
 * WAIT             : patienter, un autre FC suivra
 * OVERFLOW         : le message annonce depasse la capacite du
 *                    recepteur, la transmission doit etre abandonnee
 */
typedef enum
{
    ISOTP_FC_CONTINUE_TO_SEND = 0x0,
    ISOTP_FC_WAIT             = 0x1,
    ISOTP_FC_OVERFLOW         = 0x2
} isotp_flow_status_t;

/* ------------------------------------------------------------------ */
/* Codes de retour                                                     */
/* ------------------------------------------------------------------ */

typedef enum
{
    ISOTP_OK = 0,

    ISOTP_ERR_NULL_POINTER,
    ISOTP_ERR_BUFFER_TOO_SMALL,
    ISOTP_ERR_INVALID_LENGTH,
    ISOTP_ERR_NOT_SINGLE_FRAME,
    ISOTP_ERR_TRUNCATED_FRAME,

    ISOTP_ERR_UNEXPECTED_FRAME,   /* CF recue sans FF, FC inattendu... */
    ISOTP_ERR_SEQUENCE_NUMBER,    /* numero de sequence incorrect       */
    ISOTP_ERR_OVERFLOW,           /* message plus grand que le tampon   */
    ISOTP_ERR_TIMEOUT,            /* N_Bs ou N_Cr expire                */
    ISOTP_ERR_ABORTED,            /* interrompu par le pair             */
    ISOTP_ERR_BUSY                /* transfert deja en cours            */
} isotp_result_t;

const char *isotp_result_to_string(isotp_result_t result);
const char *isotp_frame_type_to_string(isotp_frame_type_t type);

/* ------------------------------------------------------------------ */
/* Trames isolees                                                      */
/* ------------------------------------------------------------------ */

isotp_result_t isotp_get_frame_type(const uint8_t *frame,
                                    uint8_t frame_len,
                                    isotp_frame_type_t *out_type);

isotp_result_t isotp_encode_single_frame(const uint8_t *payload,
                                         uint8_t payload_len,
                                         uint8_t *frame,
                                         uint8_t frame_capacity,
                                         uint8_t *out_frame_len);

isotp_result_t isotp_decode_single_frame(const uint8_t *frame,
                                         uint8_t frame_len,
                                         const uint8_t **out_payload,
                                         uint8_t *out_payload_len);

/*
 * Construit une trame Flow Control.
 *
 * block_size : nombre de Consecutive Frames autorisees avant le
 *              prochain FC. 0 signifie "sans limite".
 * stmin      : ecart minimal entre deux CF. 0x00 a 0x7F en
 *              millisecondes ; 0xF1 a 0xF9 pour 100 a 900 microsecondes.
 */
isotp_result_t isotp_encode_flow_control(isotp_flow_status_t status,
                                         uint8_t block_size,
                                         uint8_t stmin,
                                         uint8_t *frame,
                                         uint8_t frame_capacity,
                                         uint8_t *out_frame_len);

isotp_result_t isotp_decode_flow_control(const uint8_t *frame,
                                         uint8_t frame_len,
                                         isotp_flow_status_t *out_status,
                                         uint8_t *out_block_size,
                                         uint8_t *out_stmin);

/*
 * Convertit un champ STmin en millisecondes.
 *
 * Les valeurs sous la milliseconde sont arrondies a 1 ms : ce projet ne
 * pretend pas a une granularite microseconde sous Linux. Les valeurs
 * reservees sont ramenees a 127 ms, conformement a la recommandation de
 * la norme de traiter une valeur inconnue comme la plus prudente.
 */
uint8_t isotp_stmin_to_ms(uint8_t stmin);

/* ------------------------------------------------------------------ */
/* Reception multi-trames                                              */
/* ------------------------------------------------------------------ */

typedef enum
{
    ISOTP_RX_IDLE = 0,          /* aucun transfert en cours       */
    ISOTP_RX_WAIT_CONSECUTIVE   /* FF recue, CF attendues         */
} isotp_rx_state_t;

/*
 * Evenement produit par le traitement d'une trame recue.
 *
 * L'appelant regarde cet evenement pour savoir quoi faire :
 * emettre le Flow Control fourni, consommer le message reassemble,
 * ou ne rien faire.
 */
typedef enum
{
    ISOTP_RX_EVENT_NONE = 0,
    ISOTP_RX_EVENT_MESSAGE_READY,
    ISOTP_RX_EVENT_SEND_FLOW_CONTROL,
    ISOTP_RX_EVENT_ABORTED
} isotp_rx_event_t;

typedef struct
{
    isotp_rx_state_t state;

    uint8_t  buffer[ISOTP_MAX_PAYLOAD_SIZE];
    uint16_t expected_length;
    uint16_t received_length;

    uint8_t  next_sequence_number;

    /* Date de la derniere trame recue, pour N_Cr. */
    uint32_t last_frame_time_ms;

    /* Compteurs de telemetrie, utiles a la demonstration. */
    uint32_t stat_frames;
    uint32_t stat_messages;
    uint32_t stat_rejected;
    uint32_t stat_sequence_errors;
    uint32_t stat_overflows;
    uint32_t stat_timeouts;
} isotp_rx_context_t;

typedef struct
{
    isotp_rx_event_t event;

    /* Valides si event == MESSAGE_READY. Pointent dans le contexte. */
    const uint8_t *message;
    uint16_t       message_len;

    /* Valides si event == SEND_FLOW_CONTROL. */
    uint8_t fc_frame[ISOTP_CAN_FRAME_SIZE];
    uint8_t fc_len;

    /* Valide si event == ABORTED. */
    isotp_result_t reason;
} isotp_rx_result_t;

void isotp_rx_init(isotp_rx_context_t *ctx);

/* Ramene le contexte a l'etat repos sans effacer les compteurs. */
void isotp_rx_reset(isotp_rx_context_t *ctx);

/*
 * Traite une trame CAN recue.
 *
 * now_ms : horloge monotone en millisecondes, fournie par l'appelant.
 *
 * Le retour signale une erreur de programmation (pointeur nul). Une
 * trame malformee n'est PAS une erreur de retour : elle produit
 * l'evenement ABORTED ou NONE, avec le motif dans out->reason. Le
 * contexte reste toujours dans un etat defini.
 */
isotp_result_t isotp_rx_process(isotp_rx_context_t *ctx,
                                const uint8_t *frame,
                                uint8_t frame_len,
                                uint32_t now_ms,
                                isotp_rx_result_t *out);

/*
 * A appeler periodiquement. Si un transfert est en cours et qu'aucune
 * Consecutive Frame n'est arrivee depuis N_Cr, le transfert est
 * abandonne et le contexte revient au repos.
 */
isotp_result_t isotp_rx_poll_timeout(isotp_rx_context_t *ctx,
                                     uint32_t now_ms,
                                     isotp_rx_result_t *out);

/* ------------------------------------------------------------------ */
/* Emission multi-trames                                               */
/* ------------------------------------------------------------------ */

typedef enum
{
    ISOTP_TX_IDLE = 0,
    ISOTP_TX_WAIT_FLOW_CONTROL,
    ISOTP_TX_SENDING
} isotp_tx_state_t;

typedef enum
{
    ISOTP_TX_EVENT_NONE = 0,
    ISOTP_TX_EVENT_SEND_FRAME,  /* emettre out->frame                  */
    ISOTP_TX_EVENT_WAIT,        /* rien a emettre pour l'instant       */
    ISOTP_TX_EVENT_COMPLETE,    /* message entierement transmis        */
    ISOTP_TX_EVENT_ABORTED
} isotp_tx_event_t;

typedef struct
{
    isotp_tx_state_t state;

    /*
     * La payload est recopiee dans le contexte plutot que referencee.
     * Cela coute de la memoire statique mais supprime toute question de
     * duree de vie : l'appelant peut liberer son tampon aussitot.
     */
    uint8_t  buffer[ISOTP_MAX_PAYLOAD_SIZE];
    uint16_t total_length;
    uint16_t sent_length;

    uint8_t  next_sequence_number;

    /* Parametres imposes par le Flow Control du recepteur. */
    uint8_t  block_size;        /* 0 = sans limite */
    uint8_t  frames_in_block;
    uint8_t  stmin_ms;

    uint32_t last_frame_time_ms;
    uint32_t wait_start_ms;     /* pour N_Bs */

    uint32_t stat_messages;
    uint32_t stat_frames;
    uint32_t stat_timeouts;
} isotp_tx_context_t;

typedef struct
{
    isotp_tx_event_t event;
    uint8_t          frame[ISOTP_CAN_FRAME_SIZE];
    uint8_t          frame_len;
    isotp_result_t   reason;
} isotp_tx_result_t;

void isotp_tx_init(isotp_tx_context_t *ctx);
void isotp_tx_reset(isotp_tx_context_t *ctx);

/*
 * Demarre l'emission d'un message.
 *
 * Si le message tient dans une Single Frame, l'evenement est
 * SEND_FRAME et l'etat revient immediatement au repos : rien d'autre a
 * faire. Sinon la First Frame est produite et l'etat passe en attente
 * de Flow Control.
 */
isotp_result_t isotp_tx_start(isotp_tx_context_t *ctx,
                              const uint8_t *payload,
                              uint16_t payload_len,
                              uint32_t now_ms,
                              isotp_tx_result_t *out);

/* A appeler a la reception d'une trame Flow Control. */
isotp_result_t isotp_tx_on_flow_control(isotp_tx_context_t *ctx,
                                        const uint8_t *frame,
                                        uint8_t frame_len,
                                        uint32_t now_ms,
                                        isotp_tx_result_t *out);

/*
 * A appeler en boucle pendant une emission. Produit la Consecutive
 * Frame suivante si STmin est ecoule, signale l'expiration de N_Bs si
 * le Flow Control attendu n'arrive pas.
 */
isotp_result_t isotp_tx_poll(isotp_tx_context_t *ctx,
                             uint32_t now_ms,
                             isotp_tx_result_t *out);

#endif /* ISOTP_H */
