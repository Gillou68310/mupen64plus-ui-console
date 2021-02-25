/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *   Mupen64plus - compare_core.h                                          *
 *   Mupen64Plus homepage: https://mupen64plus.org/                        *
 *   Copyright (C) 2009 Richard Goedeken                                   *
 *   Copyright (C) 2002 Hacktarux                                          *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.          *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <assert.h>

#ifndef WIN32
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#endif

#include "compare_core.h"
#include "core_interface.h"
#include "m64p_types.h"
#include "main.h"

struct compare_data
{
    uint32_t tag;
    uint32_t size;
    uint64_t arg;
};

/* local variables */

#ifdef WIN32
#define pipename "\\\\.\\pipe\\LogPipe"
static HANDLE pipe = INVALID_HANDLE_VALUE;
#else
static int fd = -1;
#endif
static int comp_reg_32[32];
static long long comp_reg_64[32];
static unsigned int old_op = 0;
static int l_CoreCompareMode = CORE_COMPARE_DISABLE;
static int errors = 0;

static long long *ptr_reg = NULL;  /* pointer to the 64-bit general purpose registers in the core */
static int       *ptr_cop0 = NULL; /* pointer to the 32-bit Co-processor 0 registers in the core */
static long long *ptr_fgr = NULL;  /* pointer to the 64-bit floating-point registers in the core */ 
static int       *ptr_PC = NULL;   /* pointer to 32-bit R4300 Program Counter */
static FILE      *sync_file;

#define BUFFER_SIZE 0x800000
static char send_buffer[BUFFER_SIZE];
static char recv_buffer[BUFFER_SIZE];
static char tag[1024];

/* local functions */
static size_t read_pipe(void * ptr, size_t size, size_t count)
{
#ifdef WIN32
    DWORD len = 0;
    BOOL ret = 0;

    ret = ReadFile(pipe, ptr, (DWORD)(count*size), &len, NULL);
    if(ret == 0)
        return 0;
    else if(len != (DWORD)(count*size))
        return 0;
    else
        return count;
#else
    ssize_t len = read(fd, ptr, (count*size));
    if(len != (count*size))
        return 0;
    else
        return count;
#endif
}

static size_t write_pipe(void * ptr, size_t size, size_t count)
{
#ifdef WIN32
    DWORD len = 0;
    BOOL ret = 0;

    ret = WriteFile(pipe, ptr, (DWORD)(count*size), &len, NULL);
    if(ret == 0)
        return 0;
    else if(len != (DWORD)(count*size))
        return 0;
    else
        return count;
#else
    ssize_t len = write(fd, ptr, (count*size));
    if(len != (count*size))
        return 0;
    else
        return count;
#endif
}

static void stop_it(void)
{
    (*CoreDoCommand)(M64CMD_STOP, 0, NULL);
    errors++;
}

static void display_error(char *txt)
{
    int i;

    printf("err: %6s  addr:%x\t ", txt, *ptr_PC);

    if (!strcmp(txt, "PC"))
    {
        printf("My PC: %x  Ref PC: %x\t ", *ptr_PC, *comp_reg_32);
    }
    else if (!strcmp(txt, "gpr"))
    {
        for (i=0; i<32; i++)
        {
            if (ptr_reg[i] != comp_reg_64[i])
                printf("My: reg[%d]=%llx\t Ref: reg[%d]=%llx\t ", i, ptr_reg[i], i, comp_reg_64[i]);
        }
    }
    else if (!strcmp(txt, "cop0"))
    {
        for (i=0; i<32; i++)
        {
            if (ptr_cop0[i] != comp_reg_32[i])
                printf("My: reg_cop0[%d]=%x\t Ref: reg_cop0[%d]=%x\t ", i, (unsigned int)ptr_cop0[i], i, (unsigned int)comp_reg_32[i]);
        }
    }
    else if (!strcmp(txt, "cop1"))
    {
        for (i=0; i<32; i++)
        {
            if (ptr_fgr[i] != comp_reg_64[i])
                printf("My: reg[%d]=%llx\t Ref: reg[%d]=%llx\t ", i, ptr_fgr[i], i, comp_reg_64[i]);
        }
    }
    printf("\n");
    /*for (i=0; i<32; i++)
      {
     if (reg_cop0[i] != comp_reg[i])
       printf("reg_cop0[%d]=%llx != reg[%d]=%llx\n",
          i, reg_cop0[i], i, comp_reg[i]);
      }*/

    stop_it();
}

static void compare_core_sync_data(int length, void *value)
{
    static uint8_t cpt = 0;
    uint8_t _cpt = 0;

    if(errors) return;

    assert(l_CoreCompareMode != CORE_COMPARE_DISABLE);
    if (l_CoreCompareMode == CORE_COMPARE_RECV)
    {
        if (read_pipe(value, 1, length) != length)
        {
            stop_it();
            return;
        }
        if (write_pipe(&cpt, 1, 1) != 1)
        {
            stop_it();
            return;
        }
    }
    else
    {
        if (l_CoreCompareMode == CORE_COMPARE_SEND_RECORD)
        {
            fwrite(value, 1, length, sync_file);
            fflush(sync_file);
        }
        else if (l_CoreCompareMode == CORE_COMPARE_SEND_REPLAY)
        {
            fread(value, 1, length, sync_file);
        }

        if (write_pipe(value, 1, length) != length)
		{
            stop_it();
            return;
		}

        if (read_pipe(&_cpt, 1, 1) != 1)
        {
            stop_it();
            return;
        }

        if(_cpt != cpt)
        {
            DebugMessage(M64MSG_ERROR, "Compare sync data missmatch %d vs %d", _cpt, cpt);
            stop_it();
            return;
        }
    }
    cpt++;
}

static int read_tag(char *buffer, uint32_t addr)
{
    char car = 0;
    int i = 0;

    do
    {
        car = DebugMemRead8(addr++);
        *buffer++ = car;
        i++;
    }
    while(car != 0);
    return i;
}

static void read_buffer(char *buffer, uint32_t addr, uint32_t size)
{
    while(size > 0)
    {
      *buffer++ = DebugMemRead8(addr++);
      size--;
    }
}

static void print_buffer(char *buffer, uint32_t size)
{
    uint32_t i;
    for(i=0; i<size; i++)
    {
      if((i%16)==0)
        printf("\n");
      printf("%02X ", buffer[i]);
    }
}

static void compare_core_data(void *arg)
{
    struct compare_data *compare_data = (struct compare_data*)arg;
    int length;
    int64_t value;

    if(errors) return;
    assert(l_CoreCompareMode != CORE_COMPARE_DISABLE);

    if (l_CoreCompareMode == CORE_COMPARE_RECV)
    {
        length = read_tag(tag, compare_data->tag);
        if (read_pipe(recv_buffer, 1, length) != length)
        {
            DebugMessage(M64MSG_ERROR, "Compare data tag size missmatch %s vs %s", tag, recv_buffer);
            stop_it();
            return;
        }

        if(memcmp(tag, recv_buffer, length))
        {
            DebugMessage(M64MSG_ERROR, "Compare data tag missmatch %s vs %s", tag, recv_buffer);
            stop_it();
            return;
        }

        if(compare_data->size == 0) 
        {
            if (read_pipe(&value, 1, 8) != 8)
            {
                stop_it();
                return;
            }
            if(value != compare_data->arg)
            {
                DebugMessage(M64MSG_ERROR, "Compare data value missmatch tag:%s 0x%8X vs 0x%8X", tag, compare_data->arg, value);
                stop_it();
                return;
            }
        }
        else
        {
            length = compare_data->size;
            read_buffer(send_buffer, (uint32_t)compare_data->arg, length);
            if (read_pipe(recv_buffer, 1, length) != length)
            {
                DebugMessage(M64MSG_ERROR, "Compare data buffer size missmatch tag:%s", tag);
                stop_it();
                return;
            }
            if(memcmp(send_buffer, recv_buffer, length))
            {
                DebugMessage(M64MSG_ERROR, "Compare data buffer missmatch tag:%s:", tag);
                print_buffer(send_buffer, length);
                printf("\n");
                print_buffer(recv_buffer, length);
                stop_it();
                return;
            }
        }
    }
    else
    {
        length = read_tag(tag, compare_data->tag);
        if (write_pipe(tag, 1, length) != length)
        {
            stop_it();
            return;
        }
        if(compare_data->size == 0)
        {
            if (write_pipe(&compare_data->arg, 1, 8) != 8)
            {
                stop_it();
                return;
            }
        }
        else
        {
            length = compare_data->size;
            read_buffer(send_buffer, (uint32_t)compare_data->arg, length);
            if (write_pipe(send_buffer, 1, length) != length)
            {
                stop_it();
                return;
            }
        }
    }
}

static void compare_core_check(unsigned int cur_opcode)
{
    static int comparecnt = 0;
    int iFirst = 1;
    char errHead[128];
    sprintf(errHead, "Compare #%i  old_op: %x op: %x\n", comparecnt++, old_op, cur_opcode);

    /* get pointer to current R4300 Program Counter address */
    ptr_PC = (int *) DebugGetCPUDataPtr(M64P_CPU_PC); /* this changes for every instruction */

    if (l_CoreCompareMode == CORE_COMPARE_RECV)
    {
        if (read_pipe(comp_reg_32, sizeof(int), 4) != 4)
            printf("compare_core_check: read_pipe() failed");
        if (*ptr_PC != *comp_reg_32)
        {
            if (iFirst)
            {
                printf("%s", errHead);
                iFirst = 0;
            }
            display_error("PC");
        }
        if (read_pipe(comp_reg_64, sizeof(long long int), 32) != 32)
            printf("compare_core_check: read_pipe() failed");
        if (memcmp(ptr_reg, comp_reg_64, 32*sizeof(long long int)) != 0)
        {
            if (iFirst)
            {
                printf("%s", errHead);
                iFirst = 0;
            }
            display_error("gpr");
        }
        if (read_pipe(comp_reg_32, sizeof(int), 32) != 32)
            printf("compare_core_check: read_pipe() failed");
        if (memcmp(ptr_cop0, comp_reg_32, 32*sizeof(int)) != 0)
        {
            if (iFirst)
            {
                printf("%s", errHead);
                iFirst = 0;
            }
            display_error("cop0");
        }
        if (read_pipe(comp_reg_64, sizeof(long long int), 32) != 32)
            printf("compare_core_check: read_pipe() failed");
        if (memcmp(ptr_fgr, comp_reg_64, 32*sizeof(long long int)))
        {
            if (iFirst)
            {
                printf("%s", errHead);
                iFirst = 0;
            }
            display_error("cop1");
        }
        /*fread(comp_reg, 1, sizeof(int), f);
        if (memcmp(&rdram[0x31280/4], comp_reg, sizeof(int)))
          display_error("mem");*/
        /*fread (comp_reg, 4, 1, f);
        if (memcmp(&FCR31, comp_reg, 4))
          display_error();*/
        old_op = cur_opcode;
    }
    else
    {
        if (write_pipe(ptr_PC, sizeof(int), 4) != 4 ||
            write_pipe(ptr_reg, sizeof(long long int), 32) != 32 ||
            write_pipe(ptr_cop0, sizeof(int), 32) != 32 ||
            write_pipe(ptr_fgr, sizeof(long long int), 32) != 32)
            printf("compare_core_check: fwrite() failed");
        /*fwrite(&rdram[0x31280/4], 1, sizeof(int), f);
        fwrite(&FCR31, 4, 1, f);*/
    }
}

/* global functions */
void compare_core_init(int mode)
{
    /* set mode */
    l_CoreCompareMode = mode;
    sync_file = NULL;

    if(l_CoreCompareMode == CORE_COMPARE_DISABLE)
        return;

    /* get pointers to emulated R4300 CPU registers */
    ptr_reg = (long long *) DebugGetCPUDataPtr(M64P_CPU_REG_REG);
    ptr_cop0 = (int *) DebugGetCPUDataPtr(M64P_CPU_REG_COP0);
    ptr_fgr = (long long *) DebugGetCPUDataPtr(M64P_CPU_REG_COP1_FGR_64);
    /* open file handle to FIFO pipe */
    if (l_CoreCompareMode == CORE_COMPARE_RECV)
    {
#ifdef WIN32
        pipe = CreateNamedPipe(pipename, PIPE_ACCESS_INBOUND | PIPE_ACCESS_OUTBOUND, PIPE_WAIT, 1, BUFFER_SIZE, BUFFER_SIZE, 120 * 1000, NULL);

        if (pipe == INVALID_HANDLE_VALUE)
        {
            l_CoreCompareMode = CORE_COMPARE_DISABLE;
            DebugMessage(M64MSG_ERROR, "CreateNamedPipe() failed, core comparison disabled.");
            return;
        }
        ConnectNamedPipe(pipe, NULL);
#else
        mkfifo("/tmp/compare_pipe", 0600);
        DebugMessage(M64MSG_INFO, "Core Comparison Waiting to read pipe.");
        fd = open("/tmp/compare_pipe", O_RDONLY);
        if (fd < 0)
        {
            l_CoreCompareMode = CORE_COMPARE_DISABLE;
            DebugMessage(M64MSG_ERROR, "fopen() failed, core comparison disabled.");
            return;
        }
#endif
    }
    else
    {
#ifdef WIN32
        pipe = CreateFile(pipename, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

        if (pipe == INVALID_HANDLE_VALUE)
        {
            l_CoreCompareMode = CORE_COMPARE_DISABLE;
            DebugMessage(M64MSG_ERROR, "CreateFile() failed, core comparison disabled.");
            return;
        }
#else
        signal(SIGPIPE, SIG_IGN);
        DebugMessage(M64MSG_INFO, "Core Comparison Waiting to write pipe.");
        fd = open("/tmp/compare_pipe", O_WRONLY);
        if (fd < 0)
        {
            l_CoreCompareMode = CORE_COMPARE_DISABLE;
            DebugMessage(M64MSG_ERROR, "fopen() failed, core comparison disabled.");
            return;
        }
#endif
        if (l_CoreCompareMode == CORE_COMPARE_SEND_RECORD)
        {
            sync_file = fopen("sync_data.bin", "wb");
            if (sync_file == NULL)
            {
                DebugMessage(M64MSG_ERROR, "Failed to create sync_data.bin, disabling record mode...");
                l_CoreCompareMode = CORE_COMPARE_SEND;
            }
        }
        else if (l_CoreCompareMode == CORE_COMPARE_SEND_REPLAY)
        {
            sync_file = fopen("sync_data.bin", "rb");
            if (sync_file == NULL)
            {
                DebugMessage(M64MSG_ERROR, "Failed to open sync_data.bin, disabling replay mode...");
                l_CoreCompareMode = CORE_COMPARE_SEND;
            }
        }
    }

    /* set callback functions in core */
    /*if (DebugSetCoreCompare(compare_core_check, compare_core_sync_data, compare_core_data) != M64ERR_SUCCESS)*/
    if (DebugSetCoreCompare(NULL, compare_core_sync_data, compare_core_data) != M64ERR_SUCCESS)
    {
        DebugMessage(M64MSG_WARNING, "DebugSetCoreCompare() failed, core comparison disabled.");
        compare_core_shutdown();
        return;
    }
}

void compare_core_shutdown()
{
    l_CoreCompareMode = CORE_COMPARE_DISABLE;
#ifdef WIN32
    if (pipe != INVALID_HANDLE_VALUE)
        CloseHandle(pipe);
#else
    close(fd);
#endif
    if(sync_file)
        fclose(sync_file);
}

