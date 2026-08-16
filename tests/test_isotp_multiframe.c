/*
 * test_isotp_multiframe.c
 *
 * Tests de la machine a etats ISO-TP multi-trames : reception,
 * emission, numeros de sequence, debordements, temporisations.
 *
 * L'horloge est un simple entier passe en parametre. Les tests de
 * timeout n'attendent donc rien : on avance le temps a la main. C'est
 * tout l'interet d'avoir sorti le temps de la couche protocole.
 *
 * Build :
 *   make test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "isotp.h"

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

/* Contextes statiques : ils pesent plusieurs kilo-octets chacun. */
static isotp_rx_context_t g_rx;
static isotp_tx_context_t g_tx;

/* ------------------------------------------------------------------ */
/* 1. Aller-retour complet TX -> RX                                    */
/* ------------------------------------------------------------------ */
static void test_roundtrip(void)
{
    static uint8_t message[300];
    static uint8_t received[300];
    uint16_t sizes[] = { 1u, 7u, 8u, 9u, 20u, 63u, 64u, 127u, 300u };
    size_t s;

    printf("[1] Aller-retour emission -> reception\n");

    for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++)
    {
        uint16_t len = sizes[s];
        isotp_tx_result_t tx_out;
        isotp_rx_result_t rx_out;
        uint32_t now = 1000u;
        int guard;
        int completed = 0;
        uint16_t i;

        for (i = 0u; i < len; i++)
        {
            message[i] = (uint8_t)(i * 7u + 3u);
        }

        isotp_tx_init(&g_tx);
        isotp_rx_init(&g_rx);

        /* Premiere trame : SF si court, FF sinon. */
        check(isotp_tx_start(&g_tx, message, len, now, &tx_out) == ISOTP_OK,
              "demarrage emission");
        check(tx_out.event == ISOTP_TX_EVENT_SEND_FRAME,
              "une trame est produite");

        /*
         * Boucle de transfert. Le garde-fou borne le nombre de tours :
         * un transfert qui n'avance pas doit faire echouer le test, pas
         * tourner sans fin.
         */
        for (guard = 0; guard < 200; guard++)
        {
            /* Le recepteur consomme la trame produite. */
            check(isotp_rx_process(&g_rx, tx_out.frame, tx_out.frame_len,
                                   now, &rx_out) == ISOTP_OK,
                  "reception acceptee");

            if (rx_out.event == ISOTP_RX_EVENT_MESSAGE_READY)
            {
                check(rx_out.message_len == len, "longueur reassemblee");
                memcpy(received, rx_out.message, rx_out.message_len);
                check(memcmp(received, message, len) == 0,
                      "contenu reassemble identique");
                completed = 1;
                break;
            }

            if (rx_out.event == ISOTP_RX_EVENT_SEND_FLOW_CONTROL)
            {
                /* L'emetteur recoit le Flow Control et repart. */
                check(isotp_tx_on_flow_control(&g_tx, rx_out.fc_frame,
                                               rx_out.fc_len, now, &tx_out)
                      == ISOTP_OK, "flow control accepte");
            }
            else
            {
                now += 10u;
                check(isotp_tx_poll(&g_tx, now, &tx_out) == ISOTP_OK,
                      "poll emission");
            }

            if (tx_out.event != ISOTP_TX_EVENT_SEND_FRAME)
            {
                break;
            }
        }

        check(completed == 1, "message integralement transfere");
    }
}

/* ------------------------------------------------------------------ */
/* 2. Format des trames produites                                      */
/* ------------------------------------------------------------------ */
static void test_frame_formats(void)
{
    uint8_t message[20];
    isotp_tx_result_t out;
    isotp_rx_result_t rx_out;
    uint8_t i;

    printf("[2] Format des trames\n");

    for (i = 0u; i < 20u; i++)
    {
        message[i] = (uint8_t)(0xA0u + i);
    }

    isotp_tx_init(&g_tx);
    (void)isotp_tx_start(&g_tx, message, 20u, 0u, &out);

    /*
     * 20 octets = 0x014.
     * First Frame : 10 14 puis les 6 premiers octets.
     */
    check(out.frame[0] == 0x10, "PCI de First Frame, FF_DL bits 11..8 = 0");
    check(out.frame[1] == 0x14, "FF_DL bits 7..0 = 20");
    check(out.frame[2] == 0xA0 && out.frame[7] == 0xA5,
          "6 premiers octets de payload");
    check(out.frame_len == 8u, "trame pleine");

    /* Le Flow Control produit par le recepteur. */
    isotp_rx_init(&g_rx);
    (void)isotp_rx_process(&g_rx, out.frame, out.frame_len, 0u, &rx_out);
    check(rx_out.event == ISOTP_RX_EVENT_SEND_FLOW_CONTROL,
          "une First Frame declenche un Flow Control");
    check(rx_out.fc_frame[0] == 0x30, "PCI Flow Control, ContinueToSend");
    check(rx_out.fc_len == 8u, "Flow Control sur 8 octets");

    /* Premiere Consecutive Frame : numero de sequence 1. */
    (void)isotp_tx_on_flow_control(&g_tx, rx_out.fc_frame, rx_out.fc_len,
                                   0u, &out);
    check(out.event == ISOTP_TX_EVENT_SEND_FRAME, "une CF est produite");
    check(out.frame[0] == 0x21, "premiere CF : sequence 1");
    check(out.frame[1] == 0xA6, "la payload reprend au 7e octet");
}

/* ------------------------------------------------------------------ */
/* 3. Numeros de sequence                                              */
/* ------------------------------------------------------------------ */
static void test_sequence_numbers(void)
{
    uint8_t ff[8]  = { 0x10, 0x14, 1, 2, 3, 4, 5, 6 };
    uint8_t cf[8];
    isotp_rx_result_t out;
    uint8_t i;

    printf("[3] Numeros de sequence\n");

    /* --- Sequence correcte --- */
    isotp_rx_init(&g_rx);
    (void)isotp_rx_process(&g_rx, ff, 8u, 0u, &out);
    check(g_rx.state == ISOTP_RX_WAIT_CONSECUTIVE, "en attente de CF");

    cf[0] = 0x21;
    for (i = 1u; i < 8u; i++) { cf[i] = (uint8_t)(0x10u + i); }
    (void)isotp_rx_process(&g_rx, cf, 8u, 0u, &out);
    check(out.event == ISOTP_RX_EVENT_NONE, "CF 1 acceptee, message incomplet");

    /* --- Saut de sequence : 21 puis 27 au lieu de 22 --- */
    cf[0] = 0x27;
    (void)isotp_rx_process(&g_rx, cf, 8u, 0u, &out);
    check(out.event == ISOTP_RX_EVENT_ABORTED, "sequence 7 au lieu de 2 rejetee");
    check(out.reason == ISOTP_ERR_SEQUENCE_NUMBER, "motif : numero de sequence");
    check(g_rx.state == ISOTP_RX_IDLE, "contexte remis au repos");
    check(g_rx.stat_sequence_errors == 1u, "compteur d'erreurs incremente");

    /* --- CF dupliquee --- */
    isotp_rx_init(&g_rx);
    (void)isotp_rx_process(&g_rx, ff, 8u, 0u, &out);
    cf[0] = 0x21;
    (void)isotp_rx_process(&g_rx, cf, 8u, 0u, &out);
    (void)isotp_rx_process(&g_rx, cf, 8u, 0u, &out);   /* encore 1 */
    check(out.event == ISOTP_RX_EVENT_ABORTED, "CF dupliquee rejetee");
    check(out.reason == ISOTP_ERR_SEQUENCE_NUMBER, "motif : numero de sequence");

    /* --- CF isolee, sans First Frame --- */
    isotp_rx_init(&g_rx);
    cf[0] = 0x21;
    (void)isotp_rx_process(&g_rx, cf, 8u, 0u, &out);
    check(out.event == ISOTP_RX_EVENT_NONE, "CF hors transfert ignoree");
    check(out.reason == ISOTP_ERR_UNEXPECTED_FRAME, "motif : trame inattendue");
    check(g_rx.state == ISOTP_RX_IDLE, "l'etat reste au repos");

    /*
     * --- Passage de 15 a 0 ---
     * Le numero de sequence tient sur 4 bits. Apres 15 il revient a 0.
     * Un message de 120 octets force ce repli.
     */
    {
        static uint8_t big[120];
        isotp_tx_result_t tx_out;
        isotp_rx_result_t rx_out;
        uint32_t now = 0u;
        int guard;
        int done = 0;
        int saw_wrap = 0;

        for (i = 0u; i < 120u; i++) { big[i] = (uint8_t)i; }

        isotp_tx_init(&g_tx);
        isotp_rx_init(&g_rx);
        (void)isotp_tx_start(&g_tx, big, 120u, now, &tx_out);

        for (guard = 0; guard < 100; guard++)
        {
            if ((tx_out.event == ISOTP_TX_EVENT_SEND_FRAME) &&
                ((tx_out.frame[0] & 0xF0u) == 0x20u) &&
                ((tx_out.frame[0] & 0x0Fu) == 0x00u))
            {
                saw_wrap = 1;
            }

            (void)isotp_rx_process(&g_rx, tx_out.frame, tx_out.frame_len,
                                   now, &rx_out);

            if (rx_out.event == ISOTP_RX_EVENT_MESSAGE_READY)
            {
                done = (memcmp(rx_out.message, big, 120u) == 0);
                break;
            }
            if (rx_out.event == ISOTP_RX_EVENT_SEND_FLOW_CONTROL)
            {
                (void)isotp_tx_on_flow_control(&g_tx, rx_out.fc_frame,
                                               rx_out.fc_len, now, &tx_out);
            }
            else
            {
                now += 10u;
                (void)isotp_tx_poll(&g_tx, now, &tx_out);
            }
            if (tx_out.event != ISOTP_TX_EVENT_SEND_FRAME) { break; }
        }
        check(saw_wrap == 1, "le numero de sequence repasse par 0 apres 15");
        check(done == 1, "message de 120 octets reassemble malgre le repli");
    }
}

/* ------------------------------------------------------------------ */
/* 4. First Frame malformees                                           */
/* ------------------------------------------------------------------ */
static void test_malformed_first_frame(void)
{
    isotp_rx_result_t out;

    printf("[4] First Frame malformees\n");

    /* FF annoncant moins de 8 octets : aurait du etre une Single Frame. */
    {
        uint8_t ff[8] = { 0x10, 0x05, 1, 2, 3, 4, 5, 6 };
        isotp_rx_init(&g_rx);
        (void)isotp_rx_process(&g_rx, ff, 8u, 0u, &out);
        check(out.reason == ISOTP_ERR_INVALID_LENGTH,
              "FF annoncant 5 octets rejetee");
        check(g_rx.state == ISOTP_RX_IDLE, "aucun transfert ouvert");
    }

    /* FF tronquee : PCI incomplet. */
    {
        uint8_t ff[1] = { 0x10 };
        isotp_rx_init(&g_rx);
        (void)isotp_rx_process(&g_rx, ff, 1u, 0u, &out);
        check(out.reason == ISOTP_ERR_TRUNCATED_FRAME, "FF tronquee rejetee");
        check(g_rx.state == ISOTP_RX_IDLE, "aucun transfert ouvert");
    }

    /* FF sans octet de payload. */
    {
        uint8_t ff[2] = { 0x10, 0x14 };
        isotp_rx_init(&g_rx);
        (void)isotp_rx_process(&g_rx, ff, 2u, 0u, &out);
        check(out.reason == ISOTP_ERR_TRUNCATED_FRAME,
              "FF sans donnees rejetee");
    }

    /*
     * FF annoncant plus que la capacite de reassemblage.
     * Reponse attendue : Flow Control avec FlowStatus = Overflow.
     */
    {
        uint8_t ff[8] = { 0x1F, 0xFF, 1, 2, 3, 4, 5, 6 };  /* 4095 */
        isotp_rx_init(&g_rx);
        (void)isotp_rx_process(&g_rx, ff, 8u, 0u, &out);

        if (ISOTP_MAX_PAYLOAD_SIZE < 4095u)
        {
            check(out.event == ISOTP_RX_EVENT_SEND_FLOW_CONTROL,
                  "un Flow Control est emis");
            check((out.fc_frame[0] & 0x0Fu) == (uint8_t)ISOTP_FC_OVERFLOW,
                  "FlowStatus = Overflow");
        }
        else
        {
            check(out.event == ISOTP_RX_EVENT_SEND_FLOW_CONTROL,
                  "4095 octets acceptes a la capacite maximale");
        }
    }

    /* Forme etendue tronquee : FF_DL nul mais trame trop courte. */
    {
        uint8_t ff[4] = { 0x10, 0x00, 0x00, 0x00 };
        isotp_rx_init(&g_rx);
        (void)isotp_rx_process(&g_rx, ff, 4u, 0u, &out);
        check(out.reason == ISOTP_ERR_TRUNCATED_FRAME,
              "forme etendue tronquee rejetee");
    }

    /* Forme etendue annoncant 100000 octets : au-dela de toute capacite. */
    {
        uint8_t ff[8] = { 0x10, 0x00, 0x00, 0x01, 0x86, 0xA0, 0xAA, 0xBB };
        isotp_rx_init(&g_rx);
        (void)isotp_rx_process(&g_rx, ff, 8u, 0u, &out);
        check(out.event == ISOTP_RX_EVENT_SEND_FLOW_CONTROL,
              "un Flow Control d'overflow est emis");
        check((out.fc_frame[0] & 0x0Fu) == (uint8_t)ISOTP_FC_OVERFLOW,
              "FlowStatus = Overflow sur 100000 octets");
        check(g_rx.state == ISOTP_RX_IDLE, "aucune reservation faite");
        check(g_rx.stat_overflows == 1u, "compteur de debordements");
    }
}

/* ------------------------------------------------------------------ */
/* 5. Temporisations                                                   */
/* ------------------------------------------------------------------ */
static void test_timeouts(void)
{
    isotp_rx_result_t rx_out;
    isotp_tx_result_t tx_out;
    uint8_t ff[8] = { 0x10, 0x14, 1, 2, 3, 4, 5, 6 };
    uint8_t message[20];
    uint8_t i;

    printf("[5] Temporisations\n");

    /* --- N_Cr : plus aucune Consecutive Frame n'arrive --- */
    isotp_rx_init(&g_rx);
    (void)isotp_rx_process(&g_rx, ff, 8u, 1000u, &rx_out);
    check(g_rx.state == ISOTP_RX_WAIT_CONSECUTIVE, "transfert ouvert");

    (void)isotp_rx_poll_timeout(&g_rx, 1500u, &rx_out);
    check(rx_out.event == ISOTP_RX_EVENT_NONE,
          "500 ms : sous le seuil, rien ne se passe");
    check(g_rx.state == ISOTP_RX_WAIT_CONSECUTIVE, "transfert toujours ouvert");

    (void)isotp_rx_poll_timeout(&g_rx, 1000u + ISOTP_N_CR_TIMEOUT_MS, &rx_out);
    check(rx_out.event == ISOTP_RX_EVENT_ABORTED, "N_Cr expire : abandon");
    check(rx_out.reason == ISOTP_ERR_TIMEOUT, "motif : delai expire");
    check(g_rx.state == ISOTP_RX_IDLE, "contexte au repos");
    check(g_rx.stat_timeouts == 1u, "compteur de timeouts");

    /* Au repos, le poll ne declenche rien. */
    (void)isotp_rx_poll_timeout(&g_rx, 999999u, &rx_out);
    check(rx_out.event == ISOTP_RX_EVENT_NONE, "aucun timeout au repos");

    /* --- N_Bs : le Flow Control n'arrive jamais --- */
    for (i = 0u; i < 20u; i++) { message[i] = i; }

    isotp_tx_init(&g_tx);
    (void)isotp_tx_start(&g_tx, message, 20u, 5000u, &tx_out);
    check(g_tx.state == ISOTP_TX_WAIT_FLOW_CONTROL, "en attente de FC");

    (void)isotp_tx_poll(&g_tx, 5500u, &tx_out);
    check(tx_out.event == ISOTP_TX_EVENT_WAIT, "sous le seuil : on patiente");

    (void)isotp_tx_poll(&g_tx, 5000u + ISOTP_N_BS_TIMEOUT_MS, &tx_out);
    check(tx_out.event == ISOTP_TX_EVENT_ABORTED, "N_Bs expire : abandon");
    check(tx_out.reason == ISOTP_ERR_TIMEOUT, "motif : delai expire");
    check(g_tx.state == ISOTP_TX_IDLE, "emetteur au repos");
    check(g_tx.stat_timeouts == 1u, "compteur de timeouts");

    /*
     * --- Repli de l'horloge ---
     * Une horloge 32 bits en millisecondes repasse par zero au bout de
     * 49 jours. La soustraction non signee doit rester correcte.
     */
    isotp_rx_init(&g_rx);
    (void)isotp_rx_process(&g_rx, ff, 8u, 0xFFFFFF00u, &rx_out);
    (void)isotp_rx_poll_timeout(&g_rx, 0x00000100u, &rx_out);  /* +512 ms */
    check(rx_out.event == ISOTP_RX_EVENT_NONE,
          "repli d'horloge : pas de faux timeout");
    (void)isotp_rx_poll_timeout(&g_rx, 0x00000400u, &rx_out);  /* +1280 ms */
    check(rx_out.event == ISOTP_RX_EVENT_ABORTED,
          "repli d'horloge : le vrai timeout est detecte");
}

/* ------------------------------------------------------------------ */
/* 6. Flow Control                                                     */
/* ------------------------------------------------------------------ */
static void test_flow_control(void)
{
    uint8_t frame[8];
    uint8_t len;
    isotp_flow_status_t status;
    uint8_t bs;
    uint8_t stmin;
    isotp_tx_result_t tx_out;
    uint8_t message[20];
    uint8_t i;

    printf("[6] Flow Control\n");

    /* Encodage / decodage. */
    check(isotp_encode_flow_control(ISOTP_FC_CONTINUE_TO_SEND, 5u, 20u,
                                    frame, 8u, &len) == ISOTP_OK,
          "encodage accepte");
    check(frame[0] == 0x30 && frame[1] == 5u && frame[2] == 20u,
          "30 05 14");

    check(isotp_decode_flow_control(frame, len, &status, &bs, &stmin)
          == ISOTP_OK, "decodage accepte");
    check(status == ISOTP_FC_CONTINUE_TO_SEND && bs == 5u && stmin == 20u,
          "champs restitues");

    /* Flow Control tronque. */
    check(isotp_decode_flow_control(frame, 2u, &status, &bs, &stmin)
          == ISOTP_ERR_TRUNCATED_FRAME, "FC de 2 octets refuse");

    /* FlowStatus reserve. */
    {
        uint8_t bad[3] = { 0x37, 0x00, 0x00 };
        check(isotp_decode_flow_control(bad, 3u, &status, &bs, &stmin)
              == ISOTP_ERR_INVALID_LENGTH, "FlowStatus 7 refuse");
    }

    /* Conversion STmin. */
    check(isotp_stmin_to_ms(0x00u) == 0u,   "STmin 0x00 -> 0 ms");
    check(isotp_stmin_to_ms(0x7Fu) == 127u, "STmin 0x7F -> 127 ms");
    check(isotp_stmin_to_ms(0xF1u) == 1u,   "STmin 0xF1 -> arrondi a 1 ms");
    check(isotp_stmin_to_ms(0xF9u) == 1u,   "STmin 0xF9 -> arrondi a 1 ms");
    check(isotp_stmin_to_ms(0x80u) == 127u, "valeur reservee -> 127 ms");
    check(isotp_stmin_to_ms(0xFFu) == 127u, "valeur reservee -> 127 ms");

    for (i = 0u; i < 20u; i++) { message[i] = i; }

    /* --- Le recepteur refuse : FlowStatus Overflow --- */
    isotp_tx_init(&g_tx);
    (void)isotp_tx_start(&g_tx, message, 20u, 0u, &tx_out);
    {
        uint8_t fc[8] = { 0x32, 0x00, 0x00, 0, 0, 0, 0, 0 };
        (void)isotp_tx_on_flow_control(&g_tx, fc, 8u, 0u, &tx_out);
        check(tx_out.event == ISOTP_TX_EVENT_ABORTED,
              "Overflow : emission abandonnee");
        check(g_tx.state == ISOTP_TX_IDLE, "emetteur au repos");
    }

    /* --- Le recepteur demande d'attendre --- */
    isotp_tx_init(&g_tx);
    (void)isotp_tx_start(&g_tx, message, 20u, 0u, &tx_out);
    {
        uint8_t fc[8] = { 0x31, 0x00, 0x00, 0, 0, 0, 0, 0 };
        (void)isotp_tx_on_flow_control(&g_tx, fc, 8u, 100u, &tx_out);
        check(tx_out.event == ISOTP_TX_EVENT_WAIT, "Wait : on patiente");
        check(g_tx.state == ISOTP_TX_WAIT_FLOW_CONTROL, "toujours en attente");

        /* Le compteur N_Bs a ete relance a 100 ms. */
        (void)isotp_tx_poll(&g_tx, 100u + ISOTP_N_BS_TIMEOUT_MS - 1u, &tx_out);
        check(tx_out.event == ISOTP_TX_EVENT_WAIT,
              "le Wait a bien relance le compteur N_Bs");
    }

    /* --- Flow Control inattendu, hors emission --- */
    isotp_tx_init(&g_tx);
    {
        uint8_t fc[8] = { 0x30, 0x00, 0x00, 0, 0, 0, 0, 0 };
        (void)isotp_tx_on_flow_control(&g_tx, fc, 8u, 0u, &tx_out);
        check(tx_out.event == ISOTP_TX_EVENT_NONE, "FC hors emission ignore");
        check(g_tx.state == ISOTP_TX_IDLE, "aucune emission declenchee");
    }

    /*
     * --- BlockSize : l'emetteur redemande un FC apres N trames ---
     *
     * Le message doit etre assez long pour qu'il RESTE des octets apres
     * le premier bloc. 40 octets : 6 dans la First Frame, puis 5
     * Consecutive Frames. Avec BlockSize = 2, l'emetteur doit s'arreter
     * apres 2 CF et redemander l'autorisation.
     */
    isotp_tx_init(&g_tx);
    {
        static uint8_t long_message[40];
        uint8_t fc[8] = { 0x30, 0x02, 0x00, 0, 0, 0, 0, 0 };  /* BS = 2 */
        uint32_t now = 0u;
        int frames = 0;

        for (i = 0u; i < 40u; i++) { long_message[i] = i; }

        (void)isotp_tx_start(&g_tx, long_message, 40u, now, &tx_out);
        (void)isotp_tx_on_flow_control(&g_tx, fc, 8u, now, &tx_out);

        while ((tx_out.event == ISOTP_TX_EVENT_SEND_FRAME) && (frames < 10))
        {
            frames++;
            now += 5u;
            (void)isotp_tx_poll(&g_tx, now, &tx_out);
        }
        check(frames == 2, "exactement 2 CF avant un nouveau Flow Control");
        check(g_tx.state == ISOTP_TX_WAIT_FLOW_CONTROL,
              "retour en attente de Flow Control");
        check(tx_out.event == ISOTP_TX_EVENT_WAIT, "evenement d'attente");

        /* Un nouveau Flow Control relance le bloc suivant. */
        (void)isotp_tx_on_flow_control(&g_tx, fc, 8u, now, &tx_out);
        check(tx_out.event == ISOTP_TX_EVENT_SEND_FRAME,
              "le bloc suivant repart");
        check(g_tx.state == ISOTP_TX_SENDING, "emission reprise");
    }
}

/* ------------------------------------------------------------------ */
/* 7. Robustesse : balayage de trames arbitraires                      */
/* ------------------------------------------------------------------ */
static void test_fuzz_sweep(void)
{
    isotp_rx_result_t out;
    int pci;
    uint8_t len;
    int transitions = 0;

    printf("[7] Balayage : 256 PCI x 9 longueurs, dans les deux etats\n");

    /*
     * Chaque combinaison est jouee deux fois : contexte au repos, puis
     * contexte en cours de reassemblage. Le tampon est alloue a la
     * taille exacte pour qu'ASAN detecte toute lecture excedentaire.
     */
    for (pci = 0; pci <= 255; pci++)
    {
        for (len = 0u; len <= 8u; len++)
        {
            int phase;

            for (phase = 0; phase < 2; phase++)
            {
                uint8_t *frame = (uint8_t *)malloc(len ? len : 1u);
                uint8_t i;

                isotp_rx_init(&g_rx);

                if (phase == 1)
                {
                    /* Ouvrir un transfert avant d'injecter la trame. */
                    uint8_t ff[8] = { 0x10, 0x14, 1, 2, 3, 4, 5, 6 };
                    (void)isotp_rx_process(&g_rx, ff, 8u, 0u, &out);
                }

                for (i = 0u; i < len; i++)
                {
                    frame[i] = (uint8_t)(0x5Au + i);
                }
                if (len > 0u)
                {
                    frame[0] = (uint8_t)pci;
                }

                if (isotp_rx_process(&g_rx, frame, len, 0u, &out) != ISOTP_OK)
                {
                    g_failures++;
                }

                /* L'etat doit toujours rester une valeur connue. */
                if ((g_rx.state != ISOTP_RX_IDLE) &&
                    (g_rx.state != ISOTP_RX_WAIT_CONSECUTIVE))
                {
                    g_failures++;
                }

                /* La longueur recue ne depasse jamais celle annoncee. */
                if (g_rx.received_length > g_rx.expected_length)
                {
                    g_failures++;
                }

                transitions++;
                free(frame);
            }
        }
    }

    g_checks += transitions;
    check(transitions == 256 * 9 * 2, "4608 combinaisons jouees");
    printf("    -> etat toujours defini, aucun debordement ASAN\n");
}

/* ------------------------------------------------------------------ */
/* 8. Emission : cas limites                                           */
/* ------------------------------------------------------------------ */
static void test_tx_edge_cases(void)
{
    uint8_t message[10] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    isotp_tx_result_t out;

    printf("[8] Emission : cas limites\n");

    isotp_tx_init(&g_tx);

    check(isotp_tx_start(&g_tx, message, 0u, 0u, &out)
          == ISOTP_ERR_INVALID_LENGTH, "message vide refuse");
    check(isotp_tx_start(NULL, message, 5u, 0u, &out)
          == ISOTP_ERR_NULL_POINTER, "contexte NULL");
    check(isotp_tx_start(&g_tx, NULL, 5u, 0u, &out)
          == ISOTP_ERR_NULL_POINTER, "payload NULL");
    check(isotp_tx_start(&g_tx, message, 5u, 0u, NULL)
          == ISOTP_ERR_NULL_POINTER, "resultat NULL");

    /* Message trop grand pour le tampon. */
    check(isotp_tx_start(&g_tx, message,
                         (uint16_t)(ISOTP_MAX_PAYLOAD_SIZE + 1u), 0u, &out)
          == ISOTP_ERR_OVERFLOW, "message plus grand que le tampon refuse");

    /* Un message court passe en Single Frame et termine aussitot. */
    check(isotp_tx_start(&g_tx, message, 7u, 0u, &out) == ISOTP_OK,
          "7 octets acceptes");
    check(out.frame[0] == 0x07, "Single Frame, SF_DL = 7");
    check(g_tx.state == ISOTP_TX_IDLE, "aucun etat a maintenir");

    /* Emission deja en cours. */
    check(isotp_tx_start(&g_tx, message, 10u, 0u, &out) == ISOTP_OK,
          "10 octets : passage en multi-trames");
    check(g_tx.state == ISOTP_TX_WAIT_FLOW_CONTROL, "attente de FC");
    check(isotp_tx_start(&g_tx, message, 10u, 0u, &out) == ISOTP_ERR_BUSY,
          "un second demarrage est refuse");

    /* Poll au repos. */
    isotp_tx_init(&g_tx);
    check(isotp_tx_poll(&g_tx, 0u, &out) == ISOTP_OK, "poll au repos accepte");
    check(out.event == ISOTP_TX_EVENT_NONE, "aucun evenement au repos");
}

int main(void)
{
    printf("=============================================\n");
    printf(" Tests ISO-TP multi-trames\n");
    printf("=============================================\n\n");

    test_roundtrip();
    test_frame_formats();
    test_sequence_numbers();
    test_malformed_first_frame();
    test_timeouts();
    test_flow_control();
    test_fuzz_sweep();
    test_tx_edge_cases();

    printf("\n=============================================\n");
    printf(" %d verifications, %d echec(s)\n", g_checks, g_failures);
    printf("=============================================\n");

    return (g_failures == 0) ? 0 : 1;
}
