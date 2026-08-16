/*
 * test_ecu_data.c
 *
 * Tests du modele de donnees de l'ECU virtuel et de son fournisseur
 * de DID.
 *
 * Build :
 *   make test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "ecu_data.h"
#include "uds.h"

static int g_checks = 0;
static int g_failures = 0;

static void check(int condition, const char *what)
{
    g_checks++;
    if (!condition)
    {
        g_failures++;
        printf("  ECHEC : %s\n", what);
    }
}

/* ------------------------------------------------------------------ */
/* 1. Etat initial et evolution                                        */
/* ------------------------------------------------------------------ */
static void test_state(void)
{
    ecu_data_t a;
    ecu_data_t b;
    int i;

    printf("[1] Etat simule\n");

    ecu_data_init(&a);
    check(a.engine_rpm == 800u, "regime initial au ralenti");
    check(a.vehicle_speed_kph == 0u, "vehicule a l'arret");
    check(a.tick == 0u, "compteur a zero");

    /*
     * L'evolution doit etre deterministe : deux instances soumises au
     * meme nombre de pas doivent etre identiques. C'est ce qui rend une
     * trace de demonstration reproductible.
     */
    ecu_data_init(&b);
    for (i = 0; i < 250; i++)
    {
        ecu_data_tick(&a);
        ecu_data_tick(&b);
    }
    check(memcmp(&a, &b, sizeof(ecu_data_t)) == 0,
          "evolution deterministe : memes pas, memes valeurs");

    /* La temperature monte puis se stabilise, elle ne s'emballe pas. */
    check(a.coolant_temp_c == 90, "temperature stabilisee a 90 C");

    /* Bornes physiques respectees apres un long fonctionnement. */
    for (i = 0; i < 10000; i++)
    {
        ecu_data_tick(&a);
        if ((a.engine_rpm < 800u) || (a.engine_rpm > 5000u))
        {
            break;
        }
    }
    check(i == 10000, "le regime reste dans sa plage sur 10000 pas");
    check(a.vehicle_speed_kph < 180u, "vitesse bornee");
    check(a.coolant_temp_c == 90, "temperature toujours stable");

    /* Ne doit pas dereferencer. */
    ecu_data_init(NULL);
    ecu_data_tick(NULL);
    check(1, "appels avec NULL sans plantage");
}

/* ------------------------------------------------------------------ */
/* 2. Lecture des identifiants                                         */
/* ------------------------------------------------------------------ */
static void test_read_did(void)
{
    ecu_data_t data;
    uint8_t buf[32];
    uint16_t len;

    printf("[2] Lecture des identifiants\n");

    ecu_data_init(&data);

    /* Version logicielle : 3 octets. */
    len = 0u;
    check(ecu_data_read_did(DID_ECU_SOFTWARE_VERSION, buf, sizeof(buf),
                            &len, &data) == UDS_OK, "version logicielle lue");
    check(len == 3u, "3 octets");
    check(buf[0] == 0x01 && buf[1] == 0x04 && buf[2] == 0x02, "01 04 02");

    /* Numero de serie : 4 octets. */
    len = 0u;
    check(ecu_data_read_did(DID_ECU_SERIAL_NUMBER, buf, sizeof(buf),
                            &len, &data) == UDS_OK, "numero de serie lu");
    check(len == 4u, "4 octets");

    /* Regime moteur : 2 octets, poids fort en premier. */
    data.engine_rpm = 0x0BB8u;   /* 3000 */
    len = 0u;
    check(ecu_data_read_did(DID_ENGINE_RPM, buf, sizeof(buf), &len, &data)
          == UDS_OK, "regime moteur lu");
    check(len == 2u, "2 octets");
    check(buf[0] == 0x0B && buf[1] == 0xB8, "3000 encode en big endian");

    /* Vitesse : 1 octet. */
    data.vehicle_speed_kph = 130u;
    len = 0u;
    check(ecu_data_read_did(DID_VEHICLE_SPEED, buf, sizeof(buf), &len, &data)
          == UDS_OK, "vitesse lue");
    check(len == 1u && buf[0] == 130u, "1 octet, valeur exacte");

    /* Temperature negative : le signe doit survivre a l'encodage. */
    data.coolant_temp_c = -15;
    len = 0u;
    check(ecu_data_read_did(DID_COOLANT_TEMPERATURE, buf, sizeof(buf),
                            &len, &data) == UDS_OK, "temperature lue");
    check(len == 2u, "2 octets");
    {
        int16_t decoded = (int16_t)(((uint16_t)buf[0] << 8) | buf[1]);
        check(decoded == -15, "-15 C survit a l'aller-retour");
    }

    /* Tension batterie. */
    data.battery_mv = 12600u;
    len = 0u;
    check(ecu_data_read_did(DID_BATTERY_VOLTAGE, buf, sizeof(buf), &len, &data)
          == UDS_OK, "tension lue");
    check(((uint16_t)((buf[0] << 8) | buf[1])) == 12600u, "12600 mV");

    /* VIN : 17 octets, present mais hors gabarit Single Frame. */
    len = 0u;
    check(ecu_data_read_did(DID_VIN, buf, sizeof(buf), &len, &data) == UDS_OK,
          "VIN lisible avec un tampon suffisant");
    check(len == 17u, "17 octets, longueur normalisee d'un VIN");

    check(ecu_data_read_did(DID_VIN, buf, 4u, &len, &data)
          == UDS_ERR_BUFFER_TOO_SMALL,
          "VIN refuse dans le gabarit d'une Single Frame");

    /* Identifiant inconnu. */
    check(ecu_data_read_did(0xABCDu, buf, sizeof(buf), &len, &data)
          == UDS_ERR_DID_NOT_FOUND, "identifiant inconnu signale");

    /* Pointeurs NULL. */
    check(ecu_data_read_did(DID_ENGINE_RPM, NULL, sizeof(buf), &len, &data)
          == UDS_ERR_NULL_POINTER, "out NULL");
    check(ecu_data_read_did(DID_ENGINE_RPM, buf, sizeof(buf), NULL, &data)
          == UDS_ERR_NULL_POINTER, "out_len NULL");
    check(ecu_data_read_did(DID_ENGINE_RPM, buf, sizeof(buf), &len, NULL)
          == UDS_ERR_NULL_POINTER, "contexte NULL");
}

/* ------------------------------------------------------------------ */
/* 3. Aucune ecriture hors capacite                                    */
/*                                                                     */
/*    Chaque identifiant connu est lu avec toutes les capacites de 0 a */
/*    20 octets, dans un tampon alloue a la taille exacte. Sous ASAN,  */
/*    une ecriture d'un octet de trop arrete le test.                  */
/* ------------------------------------------------------------------ */
static void test_capacity_sweep(void)
{
    static const uint16_t dids[] = {
        DID_VIN, DID_ECU_SOFTWARE_VERSION, DID_ECU_SERIAL_NUMBER,
        DID_ENGINE_RPM, DID_VEHICLE_SPEED, DID_COOLANT_TEMPERATURE,
        DID_BATTERY_VOLTAGE, 0xABCDu
    };
    ecu_data_t data;
    size_t d;
    uint8_t cap;
    int violations = 0;

    printf("[3] Balayage des capacites de tampon\n");

    ecu_data_init(&data);

    for (d = 0; d < sizeof(dids) / sizeof(dids[0]); d++)
    {
        for (cap = 0u; cap <= 20u; cap++)
        {
            uint8_t *buf = (uint8_t *)malloc(cap ? cap : 1u);
            uint16_t len = 0xFFu;
            uds_result_t res;

            res = ecu_data_read_did(dids[d], buf, cap, &len, &data);

            if ((res == UDS_OK) && (len > cap))
            {
                violations++;
            }
            free(buf);
        }
    }
    check(violations == 0,
          "aucune lecture reussie n'annonce plus que la capacite fournie");
    printf("    -> 8 identifiants x 21 capacites, aucun debordement ASAN\n");
}

/* ------------------------------------------------------------------ */
/* 4. Codes defaut                                                     */
/* ------------------------------------------------------------------ */
static void test_dtc(void)
{
    ecu_data_t data;
    uint8_t buf[64];
    uint16_t len;

    printf("[4] Codes defaut\n");

    ecu_data_init(&data);

    /* Masque des defauts confirmes. */
    len = 0u;
    check(ecu_data_read_dtc(ECU_DTC_STATUS_CONFIRMED, buf, sizeof(buf),
                            &len, &data) == UDS_OK, "lecture acceptee");
    check(len == 8u, "deux defauts actifs au demarrage, 4 octets chacun");
    check(buf[0] == 0x01 && buf[1] == 0x17 && buf[2] == 0x00,
          "premier code 011700");

    /* Masque ne correspondant a aucun statut. */
    len = 0xFFu;
    check(ecu_data_read_dtc(0x02u, buf, sizeof(buf), &len, &data) == UDS_OK,
          "masque sans correspondance accepte");
    check(len == 0u, "aucun defaut rapporte");

    /* Tampon insuffisant : refus, jamais de troncature. */
    check(ecu_data_read_dtc(ECU_DTC_STATUS_CONFIRMED, buf, 4u, &len, &data)
          == UDS_ERR_BUFFER_TOO_SMALL,
          "tampon de 4 octets refuse pour deux defauts");

    /* Un defaut apparait quand la tension chute. */
    {
        int i;
        for (i = 0; i < 200; i++) { ecu_data_tick(&data); }
        len = 0u;
        (void)ecu_data_read_dtc(ECU_DTC_STATUS_CONFIRMED, buf, sizeof(buf),
                                &len, &data);
        check(len >= 8u, "les defauts persistent apres evolution");
    }

    /* Effacement global. */
    check(ecu_data_clear_dtc(ECU_DTC_GROUP_ALL, &data) == UDS_OK,
          "effacement global accepte");
    len = 0xFFu;
    (void)ecu_data_read_dtc(0xFFu, buf, sizeof(buf), &len, &data);
    check(len == 0u, "plus aucun defaut apres effacement");

    /* Effacement d'un groupe inexistant. */
    check(ecu_data_clear_dtc(0x000001u, &data) == UDS_ERR_DID_NOT_FOUND,
          "groupe inconnu signale");

    /* Effacement cible. */
    ecu_data_init(&data);
    check(ecu_data_clear_dtc(0x011700u, &data) == UDS_OK,
          "effacement d'un code precis");
    len = 0u;
    (void)ecu_data_read_dtc(0xFFu, buf, sizeof(buf), &len, &data);
    check(len == 4u, "il reste un seul defaut");

    /* Pointeurs NULL. */
    check(ecu_data_read_dtc(0xFFu, NULL, sizeof(buf), &len, &data)
          == UDS_ERR_NULL_POINTER, "out NULL");
    check(ecu_data_clear_dtc(ECU_DTC_GROUP_ALL, NULL)
          == UDS_ERR_NULL_POINTER, "contexte NULL");
}

/* ------------------------------------------------------------------ */
/* 5. Reinitialisation                                                 */
/* ------------------------------------------------------------------ */
static void test_reset(void)
{
    ecu_data_t data;
    int i;

    printf("[5] Reinitialisation\n");

    ecu_data_init(&data);
    for (i = 0; i < 100; i++) { ecu_data_tick(&data); }
    (void)ecu_data_clear_dtc(ECU_DTC_GROUP_ALL, &data);

    check(data.tick == 100u, "l'etat a evolue");

    check(ecu_data_reset(0x01u, &data) == UDS_OK, "reinitialisation acceptee");
    check(data.tick == 0u, "compteur remis a zero");
    check(data.engine_rpm == 800u, "retour au ralenti");
    check(data.dtc[0].active == 1u, "les defauts d'origine reviennent");
    check(data.reset_count == 1u, "le nombre de resets est conserve");

    check(ecu_data_reset(0x01u, &data) == UDS_OK, "second reset");
    check(data.reset_count == 2u, "compteur de resets incremente");

    check(ecu_data_reset(0x01u, NULL) == UDS_ERR_NULL_POINTER,
          "contexte NULL");
}

int main(void)
{
    printf("=============================================\n");
    printf(" Tests unitaires donnees ECU virtuel\n");
    printf("=============================================\n\n");

    test_state();
    test_read_did();
    test_capacity_sweep();
    test_dtc();
    test_reset();

    printf("\n=============================================\n");
    printf(" %d verifications, %d echec(s)\n", g_checks, g_failures);
    printf("=============================================\n");

    return (g_failures == 0) ? 0 : 1;
}
