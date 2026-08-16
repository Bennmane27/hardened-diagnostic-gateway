/*
 * ecu_data.h
 *
 * Modele de donnees de l'ECU virtuel.
 *
 * C'est la couche APPLICATION : capteurs simules, identification du
 * calculateur. Le serveur UDS n'en connait rien ; il y accede
 * uniquement via le pointeur de fonction uds_did_read_fn.
 *
 * Separation voulue : uds.c ne doit jamais contenir de regime moteur
 * ni de VIN, sinon il cesse d'etre reutilisable pour un autre ECU.
 */

#ifndef ECU_DATA_H
#define ECU_DATA_H

#include <stdint.h>

#include "uds.h"

/* ------------------------------------------------------------------ */
/* Identifiants de donnees (DID)                                       */
/*                                                                     */
/* 0xF1xx : plage d'identification definie par ISO 14229.              */
/* 0x01xx : plage constructeur, utilisee ici pour les grandeurs vives. */
/* ------------------------------------------------------------------ */

#define DID_VIN                       0xF190u  /* 17 octets */
#define DID_ECU_SOFTWARE_VERSION      0xF189u  /*  3 octets */
#define DID_ECU_SERIAL_NUMBER         0xF18Cu  /*  4 octets */

#define DID_ENGINE_RPM                0x0100u  /*  2 octets */
#define DID_VEHICLE_SPEED             0x0101u  /*  1 octet  */
#define DID_COOLANT_TEMPERATURE       0x0102u  /*  2 octets */
#define DID_BATTERY_VOLTAGE           0x0103u  /*  2 octets */

/* ------------------------------------------------------------------ */
/* Etat simule                                                         */
/* ------------------------------------------------------------------ */

typedef struct
{
    uint16_t engine_rpm;         /* tr/min                        */
    uint8_t  vehicle_speed_kph;  /* km/h                          */
    int16_t  coolant_temp_c;     /* degres Celsius, signe         */
    uint16_t battery_mv;         /* millivolts                    */

    uint32_t tick;               /* compteur d'evolution          */
} ecu_data_t;

/* Valeurs de depart, moteur au ralenti. */
void ecu_data_init(ecu_data_t *data);

/*
 * Fait evoluer les grandeurs simulees d'un pas.
 *
 * L'evolution est deterministe : elle ne depend que du compteur tick,
 * jamais d'un generateur aleatoire. Deux executions produisent la meme
 * suite de valeurs, ce qui rend une trace de demonstration
 * reproductible et un test possible.
 */
void ecu_data_tick(ecu_data_t *data);

/*
 * Fournisseur de DID branche sur le serveur UDS.
 * Signature imposee par uds_did_read_fn ; user_ctx doit pointer sur un
 * ecu_data_t.
 */
uds_result_t ecu_data_read_did(uint16_t did,
                               uint8_t *out,
                               uint16_t out_capacity,
                               uint16_t *out_len,
                               void *user_ctx);

/* Libelle lisible d'un DID, pour les traces. */
const char *ecu_data_did_to_string(uint16_t did);

#endif /* ECU_DATA_H */
