/*
 * Socket support
 *
 * Copyright 2021 Zebediah Figura for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#if 0
#pragma makedep unix
#endif

#include "config.h"
#include <errno.h>
#include <unistd.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winioctl.h"
#define USE_WS_PREFIX
#include "winsock2.h"
#include "wine/afd.h"

#include "unix_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(winsock);

#define IOCTL_AFD_RECV  CTL_CODE(FILE_DEVICE_BEEP, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)

// fixme: extern? static inline?
/*static async_data_t server_async( HANDLE handle, struct async_fileio *user, HANDLE event,
                                  PIO_APC_ROUTINE apc, void *apc_context,  client_ptr_t iosb )
{
    async_data_t async;
    async.handle      = wine_server_obj_handle( handle );
    async.user        = wine_server_client_ptr( user );
    async.iosb        = iosb;
    async.event       = wine_server_obj_handle( event );
    async.apc         = wine_server_client_ptr( apc );
    async.apc_context = wine_server_client_ptr( apc_context );
    return async;
}*/

/*static NTSTATUS wait_async( HANDLE handle, BOOL alertable, IO_STATUS_BLOCK *io )
{
    if (NtWaitForSingleObject( handle, alertable, NULL )) return STATUS_PENDING;
    return io->Status;
}*/

struct async_sock_ioctl
{
    struct async_fileio io;
    // needs work
    struct afd_recv_params recv_params;
    struct iovec iov[1];
};

static NTSTATUS sock_errno_to_status( int err )
{
    switch (err)
    {
        case EBADF:             return STATUS_INVALID_HANDLE;
        case EBUSY:             return STATUS_DEVICE_BUSY;
        case EPERM:
        case EACCES:            return STATUS_ACCESS_DENIED;
        case EFAULT:            return STATUS_NO_MEMORY;
        case EINVAL:            return STATUS_INVALID_PARAMETER;
        case ENFILE:
        case EMFILE:            return STATUS_TOO_MANY_OPENED_FILES;
        case EWOULDBLOCK:       return STATUS_DEVICE_NOT_READY;
        case EINPROGRESS:       return STATUS_PENDING;
        case EALREADY:          return STATUS_NETWORK_BUSY;
        case ENOTSOCK:          return STATUS_OBJECT_TYPE_MISMATCH;
        case EDESTADDRREQ:      return STATUS_INVALID_PARAMETER;
        case EMSGSIZE:          return STATUS_BUFFER_OVERFLOW;
        case EPROTONOSUPPORT:
        case ESOCKTNOSUPPORT:
        case EPFNOSUPPORT:
        case EAFNOSUPPORT:
        case EPROTOTYPE:        return STATUS_NOT_SUPPORTED;
        case ENOPROTOOPT:       return STATUS_INVALID_PARAMETER;
        case EOPNOTSUPP:        return STATUS_NOT_SUPPORTED;
        case EADDRINUSE:        return STATUS_ADDRESS_ALREADY_ASSOCIATED;
        case EADDRNOTAVAIL:     return STATUS_INVALID_PARAMETER;
        case ECONNREFUSED:      return STATUS_CONNECTION_REFUSED;
        case ESHUTDOWN:         return STATUS_PIPE_DISCONNECTED;
        case ENOTCONN:          return STATUS_CONNECTION_DISCONNECTED;
        case ETIMEDOUT:         return STATUS_IO_TIMEOUT;
        case ENETUNREACH:       return STATUS_NETWORK_UNREACHABLE;
        case ENETDOWN:          return STATUS_NETWORK_BUSY;
        case EPIPE:
        case ECONNRESET:        return STATUS_CONNECTION_RESET;
        case ECONNABORTED:      return STATUS_CONNECTION_ABORTED;

        case 0:                 return STATUS_SUCCESS;
        default:
            FIXME( "unknown errno %d\n", err );
            return STATUS_UNSUCCESSFUL;
    }
}

extern ssize_t CDECL __wine_locked_recvmsg( int fd, struct msghdr *hdr, int flags );

static NTSTATUS try_recv( int fd, struct async_sock_ioctl *async, ULONG_PTR *size )
{
#ifndef HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS
    char control_buffer[512];
#endif
    struct msghdr hdr;
    NTSTATUS status;
    int flags = 0;
    ssize_t ret;

    TRACE( "count %u, recv_flags %#x, msg_flags %#x, buffers[0] {%zu, %p}\n",
            async->recv_params.count, async->recv_params.recv_flags, async->recv_params.msg_flags,
            async->iov[0].iov_len, async->iov[0].iov_base );

    if (async->recv_params.msg_flags & AFD_MSG_OOB)
        flags |= MSG_OOB;
    if (async->recv_params.msg_flags & AFD_MSG_PEEK)
        flags |= MSG_PEEK;
    if (async->recv_params.msg_flags & AFD_MSG_WAITALL)
        FIXME("MSG_WAITALL is not properly supported\n");

    memset( &hdr, 0, sizeof(hdr) );
    hdr.msg_iov = async->iov;
    hdr.msg_iovlen = async->recv_params.count;
#ifndef HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS
    hdr.msg_control = control_buffer;
    hdr.msg_controllen = sizeof(control_buffer);
#endif
    while ((ret = __wine_locked_recvmsg( fd, &hdr, flags )) < 0 && errno == EINTR);

    if (ret < 0)
    {
        if (errno != EWOULDBLOCK) WARN( "recvmsg: %s\n", strerror( errno ) );
        status = sock_errno_to_status( errno );
    }
    else
    {
        status = (hdr.msg_flags & MSG_TRUNC) ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
        *size = ret;
    }

    return status;
}

static NTSTATUS async_recv_proc( void *user, IO_STATUS_BLOCK *io, NTSTATUS status )
{
    struct async_sock_ioctl *async = user;
    ULONG_PTR information = 0;
    int fd, needs_close;

    if (status == STATUS_ALERTED)
    {
        if ((status = server_get_unix_fd( async->io.handle, 0, &fd, &needs_close, NULL, NULL )))
            return status;

        status = try_recv( fd, async, &information );

        if (status == STATUS_DEVICE_NOT_READY)
            status = STATUS_PENDING;

        if (needs_close) close( fd );
    }
    if (status != STATUS_PENDING)
    {
        io->Status = status;
        io->Information = information;
        release_fileio( &async->io );
    }
    return status;
}
/*
NTSTATUS sock_ioctl( HANDLE handle, HANDLE event, PIO_APC_ROUTINE apc, void *apc_user, IO_STATUS_BLOCK *io,
                     ULONG code, void *in_buffer, ULONG in_size, void *out_buffer, ULONG out_size )
{
    int fd, needs_close;
    HANDLE wait_handle;
    NTSTATUS status;

    TRACE( "handle %p, code %#x, in_buffer %p, in_size %u, out_buffer %p, out_size %u\n",
           handle, code, in_buffer, in_size, out_buffer, out_size );

    if ((status = server_get_unix_fd( handle, 0, &fd, &needs_close, NULL, NULL )))
        return status;

    switch (code)
    {
        case IOCTL_AFD_RECV:
        {
            const struct afd_recv_params *params = in_buffer;
            struct async_sock_ioctl *async;
            ULONG_PTR information;
            DWORD async_size;
            unsigned int i;
            ULONG options;

            if (out_size) FIXME( "unexpected output size %u\n", out_size );

            if (in_size < sizeof(struct afd_recv_params))
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            async_size = offsetof( struct async_sock_ioctl, iov[params->count] );

            if ((params->msg_flags & (AFD_MSG_NOT_OOB | AFD_MSG_OOB)) == 0 ||
                (params->msg_flags & (AFD_MSG_NOT_OOB | AFD_MSG_OOB)) == (AFD_MSG_NOT_OOB | AFD_MSG_OOB))
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (!(async = (struct async_sock_ioctl *)alloc_fileio( async_size, async_recv_proc, handle )))
            {
                status = STATUS_NO_MEMORY;
                break;
            }
            async->recv_params = *params;
            for (i = 0; i < params->count; ++i)
            {
                async->iov[i].iov_base = params->buffers[i].buf;
                async->iov[i].iov_len = params->buffers[i].len;
            }

            status = try_recv( fd, async, &information );

            if (status != STATUS_SUCCESS && status != STATUS_DEVICE_NOT_READY)
            {
                free( async );
                break;
            }

            if (status == STATUS_DEVICE_NOT_READY && (async->recv_params.recv_flags & AFD_RECV_FORCE_ASYNC))
                status = STATUS_PENDING;

            if (status != STATUS_PENDING)
            {
                io->Status = status;
                io->Information = information;
            }

            SERVER_START_REQ( recv_socket )
            {
                req->status = status;
                req->async  = server_async( handle, &async->io, event, apc, apc_user, iosb_client_ptr(io) );
                status = wine_server_call( req );
                wait_handle = wine_server_ptr_handle( reply->wait );
                options     = reply->options;
            }
            SERVER_END_REQ;

            if (status != STATUS_PENDING) free( async );

            if (wait_handle) status = wait_async( wait_handle, options & FILE_SYNCHRONOUS_IO_ALERT);
            break;
        }

        case IOCTL_AFD_SELECT:
        {
            const struct afd_select_params *params = in_buffer;

            TRACE( "timeout %lld, count %u, unknown %#x, padding (%#x, %#x, %#x), sockets[0] {%04lx, %#x}\n",
                    (long long)params->timeout, params->count, params->unknown,
                    params->padding[0], params->padding[1], params->padding[2],
                    params->sockets[0].socket, params->sockets[0].flags );

            // fixme zf: we need to change ntdll. this code is going to collide with things.
            status = STATUS_NOT_SUPPORTED;
            break;
        }

        default:
        {
            FIXME( "Unknown ioctl %#x (device %#x, access %#x, function %#x, method %#x)\n",
                   code, code >> 16, (code >> 14) & 3, (code >> 2) & 0xfff, code & 3 );
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
    }

    if (needs_close) close( fd );
    return status;
}*/