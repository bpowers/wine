/*
 * Server-side console management
 *
 * Copyright (C) 1998 Alexandre Julliard
 *
 * FIXME: all this stuff is a hack to avoid breaking
 *        the client-side console support.
 */

#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "winerror.h"
#include "winnt.h"
#include "wincon.h"
#include "server/thread.h"

struct screen_buffer;

struct console_input
{
    struct object         obj;           /* object header */
    int                   fd;            /* Unix file descriptor */
    int                   mode;          /* input mode */
    struct screen_buffer *output;        /* associated screen buffer */
};

struct screen_buffer
{
    struct object         obj;           /* object header */
    int                   fd;            /* Unix file descriptor */
    int                   mode;          /* output mode */
    struct console_input *input;         /* associated console input */
    int                   cursor_size;   /* size of cursor (percentage filled) */
    int                   cursor_visible;/* cursor visibility flag */
    int                   pid;           /* xterm pid (hack) */
    char                 *title;         /* console title */
};


static void console_input_dump( struct object *obj, int verbose );
static int console_input_add_queue( struct object *obj, struct wait_queue_entry *entry );
static void console_input_remove_queue( struct object *obj, struct wait_queue_entry *entry );
static int console_input_signaled( struct object *obj, struct thread *thread );
static int console_input_get_read_fd( struct object *obj );
static void console_input_destroy( struct object *obj );

static void screen_buffer_dump( struct object *obj, int verbose );
static int screen_buffer_add_queue( struct object *obj, struct wait_queue_entry *entry );
static void screen_buffer_remove_queue( struct object *obj, struct wait_queue_entry *entry );
static int screen_buffer_signaled( struct object *obj, struct thread *thread );
static int screen_buffer_get_write_fd( struct object *obj );
static void screen_buffer_destroy( struct object *obj );

/* common routine */
static int console_get_info( struct object *obj, struct get_file_info_reply *reply );

static const struct object_ops console_input_ops =
{
    console_input_dump,
    console_input_add_queue,
    console_input_remove_queue,
    console_input_signaled,
    no_satisfied,
    console_input_get_read_fd,
    no_write_fd,
    no_flush,
    console_get_info,
    console_input_destroy
};

static const struct object_ops screen_buffer_ops =
{
    screen_buffer_dump,
    screen_buffer_add_queue,
    screen_buffer_remove_queue,
    screen_buffer_signaled,
    no_satisfied,
    no_read_fd,
    screen_buffer_get_write_fd,
    no_flush,
    console_get_info,
    screen_buffer_destroy
};

static const struct select_ops select_ops =
{
    default_select_event,
    NULL   /* we never set a timeout on a console */
};

int create_console( int fd, struct object *obj[2] )
{
    struct console_input *console_input;
    struct screen_buffer *screen_buffer;
    int read_fd, write_fd;

    if ((read_fd = (fd != -1) ? dup(fd) : dup(0)) == -1)
    {
        file_set_error();
        return 0;
    }
    if ((write_fd = (fd != -1) ? dup(fd) : dup(1)) == -1)
    {
        file_set_error();
        close( read_fd );
        return 0;
    }
    if (!(console_input = mem_alloc( sizeof(struct console_input) )))
    {
        close( read_fd );
        close( write_fd );
        return 0;
    }
    if (!(screen_buffer = mem_alloc( sizeof(struct screen_buffer) )))
    {
        close( read_fd );
        close( write_fd );
        free( console_input );
        return 0;
    }
    init_object( &console_input->obj, &console_input_ops, NULL );
    init_object( &screen_buffer->obj, &screen_buffer_ops, NULL );
    console_input->fd             = read_fd;
    console_input->mode           = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT |
                                    ENABLE_ECHO_INPUT | ENABLE_MOUSE_INPUT;
    console_input->output         = screen_buffer;
    screen_buffer->fd             = write_fd;
    screen_buffer->mode           = ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT;
    screen_buffer->input          = console_input;
    screen_buffer->cursor_size    = 100;
    screen_buffer->cursor_visible = 1;
    screen_buffer->pid            = 0;
    screen_buffer->title          = strdup( "Wine console" );
    CLEAR_ERROR();
    obj[0] = &console_input->obj;
    obj[1] = &screen_buffer->obj;
    return 1;
}

int set_console_fd( int handle, int fd, int pid )
{
    struct console_input *input;
    struct screen_buffer *output;
    struct object *obj;
    int fd_in, fd_out;

    if (!(obj = get_handle_obj( current->process, handle, 0, NULL )))
        return 0;
    if (obj->ops == &console_input_ops)
    {
        input = (struct console_input *)obj;
        output = input->output;
        grab_object( output );
    }
    else if (obj->ops == &screen_buffer_ops)
    {
        output = (struct screen_buffer *)obj;
        input = output->input;
        grab_object( input );
    }
    else
    {
        SET_ERROR( ERROR_INVALID_HANDLE );
        release_object( obj );
        return 0;
    }

    if ((fd_in = dup(fd)) == -1)
    {
        file_set_error();
        release_object( input );
        release_object( output );
        return 0;
    }
    if ((fd_out = dup(fd)) == -1)
    {
        file_set_error();
        close( fd_in );
        release_object( input );
        release_object( output );
        return 0;
    }
    close( input->fd );
    close( output->fd );
    input->fd = fd_in;
    output->fd = fd_out;
    output->pid = pid;
    release_object( input );
    release_object( output );
    return 1;
}

int get_console_mode( int handle, int *mode )
{
    struct object *obj;
    int ret = 0;

    if (!(obj = get_handle_obj( current->process, handle, GENERIC_READ, NULL )))
        return 0;
    if (obj->ops == &console_input_ops)
    {
        *mode = ((struct console_input *)obj)->mode;
        ret = 1;
    }
    else if (obj->ops == &screen_buffer_ops)
    {
        *mode = ((struct screen_buffer *)obj)->mode;
        ret = 1;
    }
    else SET_ERROR( ERROR_INVALID_HANDLE );
    release_object( obj );
    return ret;
}

int set_console_mode( int handle, int mode )
{
    struct object *obj;
    int ret = 0;

    if (!(obj = get_handle_obj( current->process, handle, GENERIC_READ, NULL )))
        return 0;
    if (obj->ops == &console_input_ops)
    {
        ((struct console_input *)obj)->mode = mode;
        ret = 1;
    }
    else if (obj->ops == &screen_buffer_ops)
    {
        ((struct screen_buffer *)obj)->mode = mode;
        ret = 1;
    }
    else SET_ERROR( ERROR_INVALID_HANDLE );
    release_object( obj );
    return ret;
}

/* set misc console information (output handle only) */
int set_console_info( int handle, struct set_console_info_request *req, const char *title )
{
    struct screen_buffer *console;
    if (!(console = (struct screen_buffer *)get_handle_obj( current->process, handle,
                                                            GENERIC_WRITE, &screen_buffer_ops )))
        return 0;
    if (req->mask & SET_CONSOLE_INFO_CURSOR)
    {
        console->cursor_size    = req->cursor_size;
        console->cursor_visible = req->cursor_visible;
    }
    if (req->mask & SET_CONSOLE_INFO_TITLE)
    {
        if (console->title) free( console->title );
        console->title = strdup( title );
    }
    release_object( console );
    return 1;
}

/* get misc console information (output handle only) */
int get_console_info( int handle, struct get_console_info_reply *reply, const char **title )
{
    struct screen_buffer *console;
    if (!(console = (struct screen_buffer *)get_handle_obj( current->process, handle,
                                                            GENERIC_READ, &screen_buffer_ops )))
        return 0;
    reply->cursor_size    = console->cursor_size;
    reply->cursor_visible = console->cursor_visible;
    reply->pid            = console->pid;
    *title                = console->title;
    release_object( console );
    return 1;
}

static void console_input_dump( struct object *obj, int verbose )
{
    struct console_input *console = (struct console_input *)obj;
    assert( obj->ops == &console_input_ops );
    fprintf( stderr, "Console input fd=%d\n", console->fd );
}

static int console_input_add_queue( struct object *obj, struct wait_queue_entry *entry )
{
    struct console_input *console = (struct console_input *)obj;
    assert( obj->ops == &console_input_ops );
    if (!obj->head)  /* first on the queue */
    {
        if (!add_select_user( console->fd, READ_EVENT, &select_ops, console ))
        {
            SET_ERROR( ERROR_OUTOFMEMORY );
            return 0;
        }
    }
    add_queue( obj, entry );
    return 1;
}

static void console_input_remove_queue( struct object *obj, struct wait_queue_entry *entry )
{
    struct console_input *console = (struct console_input *)grab_object(obj);
    assert( obj->ops == &console_input_ops );

    remove_queue( obj, entry );
    if (!obj->head)  /* last on the queue is gone */
        remove_select_user( console->fd );
    release_object( obj );
}

static int console_input_signaled( struct object *obj, struct thread *thread )
{
    fd_set fds;
    struct timeval tv = { 0, 0 };
    struct console_input *console = (struct console_input *)obj;
    assert( obj->ops == &console_input_ops );

    FD_ZERO( &fds );
    FD_SET( console->fd, &fds );
    return select( console->fd + 1, &fds, NULL, NULL, &tv ) > 0;
}

static int console_input_get_read_fd( struct object *obj )
{
    struct console_input *console = (struct console_input *)obj;
    assert( obj->ops == &console_input_ops );
    return dup( console->fd );
}

static int console_get_info( struct object *obj, struct get_file_info_reply *reply )
{
    memset( reply, 0, sizeof(*reply) );
    reply->type = FILE_TYPE_CHAR;
    return 1;
}

static void console_input_destroy( struct object *obj )
{
    struct console_input *console = (struct console_input *)obj;
    assert( obj->ops == &console_input_ops );
    close( console->fd );
    if (console->output) console->output->input = NULL;
    free( console );
}

static void screen_buffer_dump( struct object *obj, int verbose )
{
    struct screen_buffer *console = (struct screen_buffer *)obj;
    assert( obj->ops == &screen_buffer_ops );
    fprintf( stderr, "Console screen buffer fd=%d\n", console->fd );
}

static int screen_buffer_add_queue( struct object *obj, struct wait_queue_entry *entry )
{
    struct screen_buffer *console = (struct screen_buffer *)obj;
    assert( obj->ops == &screen_buffer_ops );
    if (!obj->head)  /* first on the queue */
    {
        if (!add_select_user( console->fd, WRITE_EVENT, &select_ops, console ))
        {
            SET_ERROR( ERROR_OUTOFMEMORY );
            return 0;
        }
    }
    add_queue( obj, entry );
    return 1;
}

static void screen_buffer_remove_queue( struct object *obj, struct wait_queue_entry *entry )
{
    struct screen_buffer *console = (struct screen_buffer *)grab_object(obj);
    assert( obj->ops == &screen_buffer_ops );

    remove_queue( obj, entry );
    if (!obj->head)  /* last on the queue is gone */
        remove_select_user( console->fd );
    release_object( obj );
}

static int screen_buffer_signaled( struct object *obj, struct thread *thread )
{
    fd_set fds;
    struct timeval tv = { 0, 0 };
    struct screen_buffer *console = (struct screen_buffer *)obj;
    assert( obj->ops == &screen_buffer_ops );

    FD_ZERO( &fds );
    FD_SET( console->fd, &fds );
    return select( console->fd + 1, NULL, &fds, NULL, &tv ) > 0;
}

static int screen_buffer_get_write_fd( struct object *obj )
{
    struct screen_buffer *console = (struct screen_buffer *)obj;
    assert( obj->ops == &screen_buffer_ops );
    return dup( console->fd );
}

static void screen_buffer_destroy( struct object *obj )
{
    struct screen_buffer *console = (struct screen_buffer *)obj;
    assert( obj->ops == &screen_buffer_ops );
    close( console->fd );
    if (console->input) console->input->output = NULL;
    if (console->pid) kill( console->pid, SIGTERM );
    if (console->title) free( console->title );
    free( console );
}
