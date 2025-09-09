/* xdp_loader.c - XDP 프로그램 attach/detach 및 xsk_map 추출 */

#include "xdp_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include "xdp_loader.h"

int xdp_load_program(struct xsk_socket_info *psock,
                              const char *obj_path,
                              const char *sec_name,
                              const char *map_name)
{

    int ret;
    int key = 0;
    int xskfd = 0;

    struct bpf_object *obj = NULL;
    struct bpf_map *map = NULL;

    psock->ifindex = if_nametoindex(psock->ifname);
    if ( !psock->ifindex ) 
    {
        fprintf(stderr, "if_nametoindex(%s): %s\n", psock->ifname, strerror(errno));
        return -1;
    }

    /* XDP 오브젝트 열기 */
    psock->xdp_prog = xdp_program__open_file(obj_path, sec_name, NULL);
    if ( !psock->xdp_prog ) 
    {
        fprintf(stderr, "xdp_program__open_file(%s,%s) failed\n", obj_path, sec_name);
        return -1;
    }

    /* SKB 모드 attach (generic) */
    ret = xdp_program__attach(psock->xdp_prog, psock->ifindex, XDP_FLAGS_SKB_MODE, 0);
    if (ret < 0) 
    {
        fprintf(stderr, "xdp_program__attach(%s): %s\n", psock->ifname, strerror(-ret));
        return -1;
    }

    /* xsks_map FD 추출 */
    obj = xdp_program__bpf_obj(psock->xdp_prog);
    if ( !obj ) 
    {
        fprintf(stderr, "xdp_program__bpf_obj failed\n");
        return -1;
    }

    map = bpf_object__find_map_by_name(obj, "blocklist_map");
    if ( !map ) 
    {
        fprintf(stderr, "bpf_object__find_map_by_name(xsks_map) failed\n");
        return -1;
    }

    psock->blocklist_fd = bpf_map__fd(map);
    if (psock->blocklist_fd < 0) 
    {
        fprintf(stderr, "bpf_map__fd failed\n");
        return -1;
    }


    map = bpf_object__find_map_by_name(obj, map_name);
    if ( !map ) 
    {
        fprintf(stderr, "bpf_object__find_map_by_name(xsks_map) failed\n");
        return -1;
    }

    psock->xsks_map_fd = bpf_map__fd(map);
    if (psock->xsks_map_fd < 0) 
    {
        fprintf(stderr, "bpf_map__fd failed\n");
        return -1;
    }

    /* key = queue_id, value = xsk fd */
    key = (int)psock->queue_id;
    xskfd = xsk_socket__fd(psock->xsk);

    if (bpf_map_update_elem(psock->xsks_map_fd, &key, &xskfd, BPF_ANY) < 0) 
    {
        perror("bpf_map_update_elem(xsks_map)");
        return -1;
    }

    return 0;

}

void xdp_unload_program(struct xsk_socket_info *psock) 
{

    if ( psock->xdp_prog ) 
    {
	xdp_program__detach(psock->xdp_prog, psock->ifindex, XDP_FLAGS_SKB_MODE, 0);
        xdp_program__close(psock->xdp_prog);
    }

}
