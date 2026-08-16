/*
 * ecu_data.c
 *
 * Donnees simulees de l'ECU virtuel et fournisseur de DID.
 */

#include "ecu_data.h"

/*
 * Identification statique du calculateur.
 *
 * Le VIN fait 17 caracteres, ce qui est la longueur normalisee d'un
 * numero d'identification de vehicule. Il ne tient donc PAS dans une
 * ISO-TP Single Frame : la reponse complete demanderait 3 octets
 * d'en-tete plus 17 de donnees, soit 20, contre 7 disponibles.
 *
 * Ce depassement n'est pas un accident : il est conserve tel quel pour
 * exercer le chemin responseTooLong, et il disparaitra quand le
 * transport saura emettre plusieurs trames.
 */
static const uint8_t VIN[17] =
{
    'V', 'F', '1', 'H', 'D', 'G', '2', 'A', 'X',
    '4', '7', '1', '2', '9', '3', '0', '5'
};

/* Version logicielle : majeure, mineure, correctif. */
static const uint8_t SOFTWARE_VERSION[3] = { 0x01u, 0x04u, 0x02u };

/* Numero de serie du calculateur. */
static const uint8_t SERIAL_NUMBER[4] = { 0x48u, 0x44u, 0x47u, 0x01u };

/* ------------------------------------------------------------------ */
/* Etat simule                                                         */
/* ------------------------------------------------------------------ */

void ecu_data_init(ecu_data_t *data)
{
    if (data == NULL)
    {
        return;
    }

    data->engine_rpm        = 800u;    /* ralenti      */
    data->vehicle_speed_kph = 0u;
    data->coolant_temp_c    = 21;      /* moteur froid */
    data->battery_mv        = 12600u;  /* 12,6 V       */
    data->tick              = 0u;
    data->reset_count       = 0u;

    /*
     * Deux defauts sont presents des le depart pour que la lecture ait
     * quelque chose a montrer. Un troisieme apparaitra a chaud.
     */
    data->dtc[0].code   = 0x011700u;  /* capteur de temperature */
    data->dtc[0].status = ECU_DTC_STATUS_TEST_FAILED |
                          ECU_DTC_STATUS_CONFIRMED;
    data->dtc[0].active = 1u;

    data->dtc[1].code   = 0xC12345u;  /* defaut de communication */
    data->dtc[1].status = ECU_DTC_STATUS_CONFIRMED;
    data->dtc[1].active = 1u;

    data->dtc[2].code   = 0x016200u;  /* sous-tension */
    data->dtc[2].status = 0u;
    data->dtc[2].active = 0u;

    data->dtc[3].code   = 0x010100u;  /* debitmetre d'air */
    data->dtc[3].status = 0u;
    data->dtc[3].active = 0u;
}

void ecu_data_tick(ecu_data_t *data)
{
    if (data == NULL)
    {
        return;
    }

    data->tick++;

    /*
     * Evolution deterministe et bornee. Le modulo garantit que les
     * valeurs restent dans une plage physique plausible sans jamais
     * deborder leur type.
     */
    data->engine_rpm        = (uint16_t)(800u + ((data->tick * 137u) % 4200u));
    data->vehicle_speed_kph = (uint8_t)((data->tick * 7u) % 180u);
    data->battery_mv        = (uint16_t)(12300u + ((data->tick * 11u) % 900u));

    /* Montee en temperature qui se stabilise vers 90 degres. */
    if (data->coolant_temp_c < 90)
    {
        data->coolant_temp_c = (int16_t)(data->coolant_temp_c + 1);
    }

    /*
     * Un defaut de sous-tension apparait si la batterie descend sous un
     * seuil. Le calculateur genere donc ses propres codes plutot que de
     * porter une liste figee.
     */
    if ((data->battery_mv < 12400u) && (data->dtc[2].active == 0u))
    {
        data->dtc[2].status = ECU_DTC_STATUS_TEST_FAILED |
                              ECU_DTC_STATUS_CONFIRMED;
        data->dtc[2].active = 1u;
    }
}

/* ------------------------------------------------------------------ */
/* Defauts                                                             */
/* ------------------------------------------------------------------ */

uds_result_t ecu_data_read_dtc(uint8_t status_mask,
                               uint8_t *out,
                               uint16_t out_capacity,
                               uint16_t *out_len,
                               void *user_ctx)
{
    const ecu_data_t *data = (const ecu_data_t *)user_ctx;
    uint16_t written = 0u;
    uint8_t i;

    if ((out == NULL) || (out_len == NULL) || (data == NULL))
    {
        return UDS_ERR_NULL_POINTER;
    }

    for (i = 0u; i < ECU_DTC_MAX_COUNT; i++)
    {
        if (data->dtc[i].active == 0u)
        {
            continue;
        }

        /* Le client ne veut que les defauts recoupant son masque. */
        if ((data->dtc[i].status & status_mask) == 0u)
        {
            continue;
        }

        /* Capacite verifiee AVANT ecriture, sans exception. */
        if ((uint32_t)(written + 4u) > (uint32_t)out_capacity)
        {
            return UDS_ERR_BUFFER_TOO_SMALL;
        }

        out[written]     = (uint8_t)((data->dtc[i].code >> 16) & 0xFFu);
        out[written + 1] = (uint8_t)((data->dtc[i].code >> 8) & 0xFFu);
        out[written + 2] = (uint8_t)(data->dtc[i].code & 0xFFu);
        out[written + 3] = data->dtc[i].status;

        written = (uint16_t)(written + 4u);
    }

    *out_len = written;
    return UDS_OK;
}

uds_result_t ecu_data_clear_dtc(uint32_t group_of_dtc, void *user_ctx)
{
    ecu_data_t *data = (ecu_data_t *)user_ctx;
    uint8_t i;
    uint8_t matched = 0u;

    if (data == NULL)
    {
        return UDS_ERR_NULL_POINTER;
    }

    for (i = 0u; i < ECU_DTC_MAX_COUNT; i++)
    {
        if ((group_of_dtc == ECU_DTC_GROUP_ALL) ||
            (data->dtc[i].code == group_of_dtc))
        {
            data->dtc[i].active = 0u;
            data->dtc[i].status = 0u;
            matched = 1u;
        }
    }

    /*
     * Effacer un groupe qui n'existe pas est une requete hors domaine,
     * pas un succes silencieux.
     */
    if (matched == 0u)
    {
        return UDS_ERR_DID_NOT_FOUND;
    }

    return UDS_OK;
}

uds_result_t ecu_data_reset(uint8_t reset_type, void *user_ctx)
{
    ecu_data_t *data = (ecu_data_t *)user_ctx;
    uint8_t previous_resets;

    if (data == NULL)
    {
        return UDS_ERR_NULL_POINTER;
    }

    (void)reset_type;

    previous_resets = data->reset_count;
    ecu_data_init(data);
    data->reset_count = (uint8_t)(previous_resets + 1u);

    return UDS_OK;
}

const char *ecu_data_dtc_to_string(uint32_t code)
{
    switch (code)
    {
    case 0x011700u: return "capteur de temperature moteur";
    case 0xC12345u: return "defaut de communication reseau";
    case 0x016200u: return "sous-tension batterie";
    case 0x010100u: return "debitmetre d'air";
    default:        return "defaut inconnu";
    }
}

/* ------------------------------------------------------------------ */
/* Ecriture des valeurs                                                */
/* ------------------------------------------------------------------ */

/*
 * Recopie une valeur de taille connue en verifiant d'abord la place.
 *
 * Le controle se fait AVANT la copie, jamais apres : c'est la regle qui
 * rend un debordement structurellement impossible plutot que detecte
 * trop tard.
 */
static uds_result_t emit_bytes(const uint8_t *src,
                               uint8_t src_len,
                               uint8_t *out,
                               uint16_t out_capacity,
                               uint16_t *out_len)
{
    uint8_t i;

    if (src_len > out_capacity)
    {
        return UDS_ERR_BUFFER_TOO_SMALL;
    }

    for (i = 0u; i < src_len; i++)
    {
        out[i] = src[i];
    }

    *out_len = src_len;
    return UDS_OK;
}

/* Entier 16 bits, poids fort en premier (convention UDS). */
static uds_result_t emit_u16(uint16_t value,
                             uint8_t *out,
                             uint16_t out_capacity,
                             uint16_t *out_len)
{
    uint8_t buf[2];

    buf[0] = (uint8_t)((value >> 8) & 0xFFu);
    buf[1] = (uint8_t)(value & 0xFFu);

    return emit_bytes(buf, 2u, out, out_capacity, out_len);
}

uds_result_t ecu_data_read_did(uint16_t did,
                               uint8_t *out,
                               uint16_t out_capacity,
                               uint16_t *out_len,
                               void *user_ctx)
{
    const ecu_data_t *data = (const ecu_data_t *)user_ctx;

    if ((out == NULL) || (out_len == NULL) || (data == NULL))
    {
        return UDS_ERR_NULL_POINTER;
    }

    switch (did)
    {
    case DID_VIN:
        return emit_bytes(VIN, (uint8_t)sizeof(VIN),
                          out, out_capacity, out_len);

    case DID_ECU_SOFTWARE_VERSION:
        return emit_bytes(SOFTWARE_VERSION, (uint8_t)sizeof(SOFTWARE_VERSION),
                          out, out_capacity, out_len);

    case DID_ECU_SERIAL_NUMBER:
        return emit_bytes(SERIAL_NUMBER, (uint8_t)sizeof(SERIAL_NUMBER),
                          out, out_capacity, out_len);

    case DID_ENGINE_RPM:
        return emit_u16(data->engine_rpm, out, out_capacity, out_len);

    case DID_VEHICLE_SPEED:
        return emit_bytes(&data->vehicle_speed_kph, 1u,
                          out, out_capacity, out_len);

    case DID_COOLANT_TEMPERATURE:
        /*
         * Valeur signee transmise telle quelle sur 16 bits. La
         * conversion vers uint16_t est explicite pour que le decalage
         * porte sur un type non signe : decaler un entier signe negatif
         * est un comportement que l'on evite.
         */
        return emit_u16((uint16_t)data->coolant_temp_c,
                        out, out_capacity, out_len);

    case DID_BATTERY_VOLTAGE:
        return emit_u16(data->battery_mv, out, out_capacity, out_len);

    default:
        return UDS_ERR_DID_NOT_FOUND;
    }
}

const char *ecu_data_did_to_string(uint16_t did)
{
    switch (did)
    {
    case DID_VIN:
        return "VIN";
    case DID_ECU_SOFTWARE_VERSION:
        return "ECU software version";
    case DID_ECU_SERIAL_NUMBER:
        return "ECU serial number";
    case DID_ENGINE_RPM:
        return "engine RPM";
    case DID_VEHICLE_SPEED:
        return "vehicle speed";
    case DID_COOLANT_TEMPERATURE:
        return "coolant temperature";
    case DID_BATTERY_VOLTAGE:
        return "battery voltage";
    default:
        return "identifiant inconnu";
    }
}
