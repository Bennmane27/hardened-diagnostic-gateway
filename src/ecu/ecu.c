#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#include <net/if.h>

int main(void)
{
    int socket_fd;
    struct sockaddr_can addr;
    struct ifreq ifr;
    struct can_frame rx_frame;
    struct can_frame tx_frame;

    socket_fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);

    if (socket_fd < 0)
    {
        perror("socket");
        return 1;
    }

    strcpy(ifr.ifr_name, "vcan0");

    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl");
        close(socket_fd);
        return 1;
    }

    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(socket_fd);
        return 1;
    }

    printf("ECU virtuel demarre\n");
    printf("En attente d'une trame sur 0x7E0...\n");

    while (1)
    {
        if (read(socket_fd, &rx_frame, sizeof(rx_frame)) < 0)
        {
            perror("read");
            break;
        }

        if (rx_frame.can_id == 0x7E0)
        {
            printf("\nTrame recue\n");
            printf("ID : 0x%X\n", rx_frame.can_id);

            printf("DATA : ");

            for (int i = 0; i < rx_frame.can_dlc; i++)
            {
                printf("%02X ", rx_frame.data[i]);
            }

            printf("\n");

            tx_frame.can_id = 0x7E8;
            tx_frame.can_dlc = 8;

            tx_frame.data[0] = 0xAA;
            tx_frame.data[1] = 0xBB;
            tx_frame.data[2] = 0xCC;
            tx_frame.data[3] = 0xDD;
            tx_frame.data[4] = 0x11;
            tx_frame.data[5] = 0x22;
            tx_frame.data[6] = 0x33;
            tx_frame.data[7] = 0x44;

            if (write(socket_fd, &tx_frame, sizeof(tx_frame)) != sizeof(tx_frame))
            {
                perror("write");
                break;
            }

            printf("Reponse envoyee sur 0x7E8\n");
        }
    }

    close(socket_fd);

    return 0;
}
