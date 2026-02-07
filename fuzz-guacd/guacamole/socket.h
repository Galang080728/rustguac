/*
 * Minimal socket.h stub for fuzzing — only the forward typedef is needed.
 * parser.h includes socket-types.h which defines guac_socket, but parser.c
 * also includes this full header. We stub it to avoid pulling in client-types.h
 * and the rest of the socket API.
 */
#ifndef _GUAC_SOCKET_H
#define _GUAC_SOCKET_H
#include "socket-types.h"
#endif
