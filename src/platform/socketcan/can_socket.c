/*
 * can_socket.c
 *
 * Implementation SocketCAN de l'adaptateur transport.
 */

#include "can_socket.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#include <net/if.h>

int can_socket_open(can_socket_t *sock,
                    const char *interface_name,
                    uint32_t rx_timeout_ms)
{
    struct sockaddr_can addr;
    struct ifreq ifr;
    struct timeval timeout;

    if ((sock == NULL) || (interface_name == NULL))
    {
        return -1;
    }

    sock->fd = -1;

    /*
     * PF_CAN + SOCK_RAW + CAN_RAW : un socket qui transporte des trames
     * CAN brutes, sans aucune couche protocole intermediaire. C'est
     * l'equivalent CAN d'un socket raw IP.
     */
    sock->fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (sock->fd < 0)
    {
        perror("socket");
        return -1;
    }

    /*
     * Le noyau designe les interfaces par un index numerique, pas par
     * leur nom. SIOCGIFINDEX fait la traduction "vcan0" -> index.
     */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);

    if (ioctl(sock->fd, SIOCGIFINDEX, &ifr) < 0)
    {
        fprintf(stderr, "interface '%s' introuvable : %s\n",
                interface_name, strerror(errno));
        close(sock->fd);
        sock->fd = -1;
        return -1;
    }

    /* memset : le reste de la structure doit etre a zero. */
    memset(&addr, 0, sizeof(addr));
    addr.can_family  = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(sock->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(sock->fd);
        sock->fd = -1;
        return -1;
    }

    if (rx_timeout_ms > 0u)
    {
        timeout.tv_sec  = (time_t)(rx_timeout_ms / 1000u);
        timeout.tv_usec = (suseconds_t)((rx_timeout_ms % 1000u) * 1000u);

        if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO,
                       &timeout, sizeof(timeout)) < 0)
        {
            perror("setsockopt");
            close(sock->fd);
            sock->fd = -1;
            return -1;
        }
    }

    return 0;
}

void can_socket_close(can_socket_t *sock)
{
    if ((sock != NULL) && (sock->fd >= 0))
    {
        close(sock->fd);
        sock->fd = -1;
    }
}

int can_socket_send(can_socket_t *sock,
                    uint32_t can_id,
                    const uint8_t *data,
                    uint8_t len)
{
    struct can_frame frame;
    uint8_t i;

    if ((sock == NULL) || (sock->fd < 0) || (data == NULL))
    {
        return -1;
    }

    if (len > CAN_MAX_DLEN)
    {
        return -1;
    }

    memset(&frame, 0, sizeof(frame));
    frame.can_id  = can_id;
    frame.can_dlc = len;

    for (i = 0u; i < len; i++)
    {
        frame.data[i] = data[i];
    }

    if (write(sock->fd, &frame, sizeof(frame)) != (ssize_t)sizeof(frame))
    {
        perror("write");
        return -1;
    }

    return 0;
}

int can_socket_recv(can_socket_t *sock,
                    uint32_t *out_can_id,
                    uint8_t *out_data,
                    uint8_t *out_len)
{
    struct can_frame frame;
    ssize_t n;
    uint8_t i;

    if ((sock == NULL) || (sock->fd < 0) ||
        (out_can_id == NULL) || (out_data == NULL) || (out_len == NULL))
    {
        return -1;
    }

    n = read(sock->fd, &frame, sizeof(frame));

    if (n < 0)
    {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK) || (errno == EINTR))
        {
            return 0;   /* delai expire, pas une erreur */
        }
        perror("read");
        return -1;
    }

    if (n < (ssize_t)sizeof(frame))
    {
        return 0;
    }

    /*
     * can_id porte l'identifiant ET des drapeaux dans ses bits hauts :
     *   CAN_EFF_FLAG  trame a identifiant etendu
     *   CAN_RTR_FLAG  remote transmission request
     *   CAN_ERR_FLAG  trame d'erreur
     *
     * Comparer can_id brut a 0x7E0 marche par hasard tant que personne
     * n'emet de trame etendue. On filtre donc explicitement.
     */
    if ((frame.can_id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) != 0u)
    {
        return 0;   /* ni erreur ni RTR ne nous concernent */
    }

    if ((frame.can_id & CAN_EFF_FLAG) != 0u)
    {
        *out_can_id = frame.can_id & CAN_EFF_MASK;
    }
    else
    {
        *out_can_id = frame.can_id & CAN_SFF_MASK;
    }

    *out_len = (frame.can_dlc > CAN_MAX_DLEN) ? CAN_MAX_DLEN : frame.can_dlc;

    for (i = 0u; i < *out_len; i++)
    {
        out_data[i] = frame.data[i];
    }

    return 1;
}

uint32_t can_monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        return 0u;
    }

    return (uint32_t)(((uint64_t)ts.tv_sec * 1000u) +
                      ((uint64_t)ts.tv_nsec / 1000000u));
}
