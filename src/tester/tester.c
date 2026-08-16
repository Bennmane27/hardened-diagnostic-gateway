#include <stdio.h>
#include <stdlib.h>
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
    struct can_frame frame;

    /* Create a raw CAN socket. */
    socket_fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (socket_fd < 0)
    {
        perror("socket");
        return 1;
    }

    /* Resolve the Linux interface index for vcan0. */
    strcpy(ifr.ifr_name, "vcan0");
    if (ioctl(socket_fd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("ioctl");
        close(socket_fd);
        return 1;
    }

    /* Bind the socket to vcan0. */
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(socket_fd);
        return 1;
    }

    /* Build one classic CAN frame. */
    frame.can_id = 0x7E0;
    frame.can_dlc = 8;
    frame.data[0] = 0x11;
    frame.data[1] = 0x22;
    frame.data[2] = 0x33;
    frame.data[3] = 0x44;
    frame.data[4] = 0x55;
    frame.data[5] = 0x66;
    frame.data[6] = 0x77;
    frame.data[7] = 0x88;

    /* Transmit the frame on the virtual CAN bus. */
    if (write(socket_fd, &frame, sizeof(frame)) != sizeof(frame))
    {
        perror("write");
        close(socket_fd);
        return 1;
    }

    printf("CAN frame sent on vcan0\n");
    printf("ID: 0x%X\n", frame.can_id);

    close(socket_fd);
    return 0;
}
