#ifndef XDP_LOADER_H
#define XDP_LOADER_H

#include "xdp_util.h"

// XDP attach 함수
// 인터페이스 이름을 받아 해당 인터페이스에 xdp_prog_kern.o를 attach
// attach 후 xsk_map의 map fd를 map_fd_out에 반환
int xdp_load_program(struct xsk_socket_info *psock,
                              const char *obj_path,
                              const char *sec_name,
                              const char *map_name);

// XDP detach 함수
// 인터페이스 이름을 받아 해당 인터페이스의 XDP 프로그램을 해제
void xdp_unload_program(struct xsk_socket_info *psock);

#endif // XDP_LOADER_H
