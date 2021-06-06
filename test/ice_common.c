#include <stdio.h>
#include <sys/types.h>
#if !defined(WIN32)
#include <sys/socket.h>
#include <netdb.h>
#endif
#if defined(__VMS)
#include <ioctl.h>
#endif
#include <fcntl.h>
#include "ice_common.h"
#include <string.h>

int make_publish_msg(char* buf, int max_buf_size, int msg_type, const char* msg)
{
    int new_msg_len = 0;
    int msg_type_net_order = htonl(msg_type);
    memcpy(buf, &msg_type_net_order, sizeof (msg_type));
    new_msg_len += sizeof (msg_type);
    if (NULL != msg) {
        strcpy (buf + new_msg_len, msg);
        new_msg_len += strlen(msg);
    }
    buf[new_msg_len] = 0;
    new_msg_len += 1;
    return new_msg_len;
}

