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

#include "compare_core.h"
#include "core_interface.h"
#include "m64p_types.h"
#include "main.h"

/* local variables */

#ifdef WIN32
#define pipename "\\\\.\\pipe\\LogPipe"
static HANDLE pipe = INVALID_HANDLE_VALUE;
#else
static FILE *fPipe = NULL;
#endif
static int comp_reg_32[32];
static long long comp_reg_64[32];
static int l_CoreCompareMode = CORE_COMPARE_DISABLE;

static long long *ptr_reg = NULL;  /* pointer to the 64-bit general purpose registers in the core */
static int       *ptr_cop0 = NULL; /* pointer to the 32-bit Co-processor 0 registers in the core */
static long long *ptr_fgr = NULL;  /* pointer to the 64-bit floating-point registers in the core */
static int       *ptr_PC = NULL;   /* pointer to 32-bit R4300 Program Counter */
static int       *ptr_fcr0 = NULL;
static int       *ptr_fcr31 = NULL;
static long long *ptr_hi = NULL;
static long long *ptr_lo = NULL;
static FILE      *sync_file;
static FILE      *comp_file;

static const char cop0name[32][32] = {
  "CP0_INDEX_REG",
  "CP0_RANDOM_REG",
  "CP0_ENTRYLO0_REG",
  "CP0_ENTRYLO1_REG",
  "CP0_CONTEXT_REG",
  "CP0_PAGEMASK_REG",
  "CP0_WIRED_REG",
  "7",
  "CP0_BADVADDR_REG",
  "CP0_COUNT_REG",
  "CP0_ENTRYHI_REG",
  "CP0_COMPARE_REG",
  "CP0_STATUS_REG",
  "CP0_CAUSE_REG",
  "CP0_EPC_REG",
  "CP0_PREVID_REG",
  "CP0_CONFIG_REG",
  "CP0_LLADDR_REG",
  "CP0_WATCHLO_REG",
  "CP0_WATCHHI_REG",
  "CP0_XCONTEXT_REG",
  "21",
  "22",
  "23",
  "24",
  "25",
  "26",
  "27",
  "CP0_TAGLO_REG",
  "CP0_TAGHI_REG",
  "CP0_ERROREPC_REG",
  "31"
};

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
    return fread(ptr, size, count, fPipe);
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
    return fwrite(ptr, size, count, fPipe);
#endif
}

static void stop_it(void)
{
    static int errors = 0;

    (*CoreDoCommand)(M64CMD_STOP, 0, NULL);

    errors++;
#if !defined(WIN32)
    #if defined(__i386__) || defined(__x86_64__)
        if (errors > 7)
            asm("int $3;");
    #endif
#endif
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
    else if (!strcmp(txt, "hi"))
    {
        printf("My hi: %llx  Ref hi: %llx\t ", *ptr_hi, *comp_reg_64);
    }
    else if (!strcmp(txt, "lo"))
    {
        printf("My lo: %llx  Ref lo: %llx\t ", *ptr_lo, *comp_reg_64);
    }
    else if (!strcmp(txt, "fcr0"))
    {
        printf("My fcr0: %x  Ref fcr0: %x\t ", *ptr_fcr0, *comp_reg_32);
    }
    else if (!strcmp(txt, "fcr31"))
    {
        printf("My fcr31: %x  Ref fcr31: %x\t ", *ptr_fcr31, *comp_reg_32);
    }

    printf("\n");

    stop_it();
}

static void compare_core_sync_data(int length, void *value)
{
    assert(l_CoreCompareMode != CORE_COMPARE_DISABLE);
    if (l_CoreCompareMode == CORE_COMPARE_RECV)
    {
        if (read_pipe(value, 1, length) != length)
            stop_it();
    }
    else
    {
        if (l_CoreCompareMode == CORE_COMPARE_SEND_RECORD)
        {
            fwrite(value, 1, length, sync_file);
            fwrite(&ptr_cop0[9], 1, 4, sync_file);
            fflush(sync_file);
        }
        else if (l_CoreCompareMode == CORE_COMPARE_SEND_REPLAY)
        {
            fread(value, 1, length, sync_file);
            if(fread(comp_reg_32, 1, 4, sync_file) == 4)
            {
                if(comp_reg_32[0] != ptr_cop0[9])
                {
                    printf("compare_core replay out of sync!!!");
                    stop_it();
                }
            }
        }

        if (write_pipe(value, 1, length) != length)
            stop_it();
    }
}

void print_state(unsigned int op)
{
  int i;
  fprintf(comp_file,"%d\n", op);
  //fprintf(comp_file,"ds: %d\n", r4300->delay_slot);
  fprintf(comp_file,"pcaddr: 0x%08x\n", *ptr_PC);
  fprintf(comp_file,"fcr0: 0x%08x\n", *ptr_fcr0);
  fprintf(comp_file,"fcr31: 0x%08x\n", *ptr_fcr31);
  //fprintf(comp_file,"hi: 0x%016llx\n", *ptr_hi);
  //fprintf(comp_file,"lo: 0x%016llx\n", *ptr_lo);
  //fprintf(comp_file,"rdram: 0x%08x\n", rdram_checksum(0));
  fprintf(comp_file,"\n");
  
  //if(0)
  {
    /*for(i=0;i<32;i++)
      fprintf(comp_file,"regs[%d]:0x%016llx\n",i,ptr_reg[i]);
    fprintf(comp_file,"\n");*/

    for(i=0;i<32;i++)
      fprintf(comp_file,"cop0[%s]:0x%08x\n",cop0name[i],ptr_cop0[i]);
    fprintf(comp_file,"\n");

    for(i=0;i<32;i++)
      fprintf(comp_file,"cop1[%d]:0x%016llx\n",i,ptr_fgr[i]);
    fprintf(comp_file,"\n");
  }
  fflush(comp_file);
}

static void compare_core_check(unsigned int cur_opcode)
{
    static int comparecnt = 0;
    static int compare = 0;
    comparecnt++;
    int interrupt = cur_opcode==0;

    /* get pointer to current R4300 Program Counter address */
    ptr_PC = (int *) DebugGetCPUDataPtr(M64P_CPU_PC); /* this changes for every instruction */
    assert(ptr_PC);

    //last good interrupt
    if((*ptr_PC == 0)&&(ptr_cop0[9]==0))
        compare = 1;

    if(!(interrupt||compare))
        return;

    print_state(cur_opcode);

    //debug after instruction
    if((*ptr_PC == 0)&&(ptr_cop0[9]==0))
        compare = 1;

    assert(l_CoreCompareMode != CORE_COMPARE_DISABLE);
    if (l_CoreCompareMode == CORE_COMPARE_RECV)
    {
        if (read_pipe(comp_reg_32, sizeof(int), 1) != 1)
            printf("compare_core_check: read_pipe() failed");
        if (*ptr_PC != *comp_reg_32)
            display_error("PC");

        if (read_pipe(comp_reg_64, sizeof(long long int), 32) != 32)
            printf("compare_core_check: read_pipe() failed");
        /*if (memcmp(ptr_reg, comp_reg_64, 32*sizeof(long long int)) != 0)
            display_error("gpr");*/

        if (read_pipe(comp_reg_32, sizeof(int), 32) != 32)
            printf("compare_core_check: read_pipe() failed");
        if (memcmp(ptr_cop0, comp_reg_32, 32*sizeof(int)) != 0)
            display_error("cop0");

        if (read_pipe(comp_reg_64, sizeof(long long int), 32) != 32)
            printf("compare_core_check: read_pipe() failed");
        if (memcmp(ptr_fgr, comp_reg_64, 32*sizeof(long long int)))
            display_error("cop1");

        if (read_pipe(comp_reg_64, sizeof(long long int), 1) != 1)
            printf("compare_core_check: read_pipe() failed");
        /*if (*ptr_hi != *comp_reg_64)
            display_error("hi");*/

        if (read_pipe(comp_reg_64, sizeof(long long int), 1) != 1)
            printf("compare_core_check: read_pipe() failed");
        /*if (*ptr_lo != *comp_reg_64)
            display_error("lo");*/

        if (read_pipe(comp_reg_32, sizeof(int), 1) != 1)
            printf("compare_core_check: read_pipe() failed");
        if (*ptr_fcr0 != *comp_reg_32)
            display_error("fcr0");

        if (read_pipe(comp_reg_32, sizeof(int), 1) != 1)
            printf("compare_core_check: read_pipe() failed");
        if (*ptr_fcr31 != *comp_reg_32)
            display_error("fcr31");
    }
    else
    {
        if (write_pipe(ptr_PC, sizeof(int), 1) != 1 ||
            write_pipe(ptr_reg, sizeof(long long int), 32) != 32 ||
            write_pipe(ptr_cop0, sizeof(int), 32) != 32 ||
            write_pipe(ptr_fgr, sizeof(long long int), 32) != 32 ||
            write_pipe(ptr_hi, sizeof(long long int), 1) != 1 ||
            write_pipe(ptr_lo, sizeof(long long int), 1) != 1 ||
            write_pipe(ptr_fcr0, sizeof(int), 1) != 1 ||
            write_pipe(ptr_fcr31, sizeof(int), 1) != 1)
        {
            printf("compare_core_check: write_pipe() failed");
            stop_it();
        }
    }
}

/* global functions */
void compare_core_init(int mode)
{
    /* set mode */
    l_CoreCompareMode = mode;

    /* get pointers to emulated R4300 CPU registers */
    ptr_reg = (long long *) DebugGetCPUDataPtr(M64P_CPU_REG_REG);
    ptr_cop0 = (int *) DebugGetCPUDataPtr(M64P_CPU_REG_COP0);
    ptr_fgr = (long long *) DebugGetCPUDataPtr(M64P_CPU_REG_COP1_FGR_64);
    ptr_fcr0 = (int *)DebugGetCPUDataPtr(M64P_CPU_REG_COP1_FCR0);
    ptr_fcr31 = (int *)DebugGetCPUDataPtr(M64P_CPU_REG_COP1_FCR31);
    ptr_hi = (long long *)DebugGetCPUDataPtr(M64P_CPU_REG_HI);
    ptr_lo = (long long *)DebugGetCPUDataPtr(M64P_CPU_REG_LO);

    /* open file handle to FIFO pipe */
    if (l_CoreCompareMode == CORE_COMPARE_RECV)
    {
#ifdef WIN32
        pipe = CreateNamedPipe(pipename, PIPE_ACCESS_INBOUND | PIPE_ACCESS_OUTBOUND, PIPE_WAIT, 1, 1024, 1024, 120 * 1000, NULL);

        if (pipe == INVALID_HANDLE_VALUE)
        {
            l_CoreCompareMode = CORE_COMPARE_DISABLE;
            DebugMessage(M64MSG_ERROR, "CreateNamedPipe() failed, core comparison disabled.");
            return;
        }
        ConnectNamedPipe(pipe, NULL);
#else
        mkfifo("/tmp/compare_pipe", 0600); //Ignore fail if file exist
        DebugMessage(M64MSG_INFO, "Core Comparison Waiting to read pipe.");
        fPipe = fopen("/tmp/compare_pipe", "r");
        if (fPipe == NULL)
        {
            l_CoreCompareMode = CORE_COMPARE_DISABLE;
            DebugMessage(M64MSG_ERROR, "fopen() failed, core comparison disabled.");
            return;
        }
#endif
        comp_file = fopen("recv.txt", "w");
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
        DebugMessage(M64MSG_INFO, "Core Comparison Waiting to write pipe.");
        fPipe = fopen("/tmp/compare_pipe", "w");
        if (fPipe == NULL)
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
        comp_file = fopen("send.txt", "w");
    }

    /* set callback functions in core */
    if (DebugSetCoreCompare(compare_core_check, compare_core_sync_data) != M64ERR_SUCCESS)
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
    fclose(fPipe);
#endif
    if ((l_CoreCompareMode == CORE_COMPARE_SEND_RECORD) || (l_CoreCompareMode == CORE_COMPARE_SEND_REPLAY))
        fclose(sync_file);

    fclose(comp_file);
}

