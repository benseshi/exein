/* Copyright 2020 Exein. All Rights Reserved.

Licensed under the GNU General Public License, Version 3.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.gnu.org/licenses/gpl-3.0.html

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/


#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <semaphore.h>

#define CELLS_NUMBER 256
#define BUF_NUM 8  //be aware that this number is bound to the map attibute of shared_buffers
#define BUF_SIZE 128

#define ISBUSY 0xff
#define ISFREE 0x00
#define ISOK 0xff
#define ISKO 0x00

#ifndef DODEBUG
#ifdef DEBUG
#define DODEBUG( ... ) printf( __VA_ARGS__ );
#else
#define DODEBUG( ... ) do { } while(0)
#endif
#endif

#define SHM_SIZE(reserved,generic_element_size,num) sizeof(meallocator)+reserved+(generic_element_size<<(num>>5))
#define SHM_NTH_EL_ADDR(reserved,generic_element_size,num) sizeof(meallocator)+reserved+(generic_element_size*num)
#define RESERVED2BASE(reserved) (void *)(((char *)reserved)-sizeof(meallocator))
#define BASE2RESERVED(base) (void *)(((char *)base)+sizeof(meallocator))


typedef struct {
	uint32_t		map[CELLS_NUMBER>>5];
	uint32_t		generic_element_size, reserved;
} meallocator;

typedef struct {
	sem_t                   semaphore;
	uint8_t			map;
	uint8_t			busy;
	char			buffzone[BUF_NUM*BUF_SIZE];
} shared_buffers;

shared_buffers *sbuff_init();
void *get_sbuff(shared_buffers *b);
void rel_sbuf(shared_buffers *b, void *addr);
void sbuff_destroy(shared_buffers *b);

void *mealloc_init(uint32_t reserved, uint32_t generic_element_size);
void mealloc_destroy(void *shm);
void *mealloc(void *shm);
void *get_reserved_addr(void *shm);
void mefree(meallocator *shm, void *addr);
void c_free(meallocator *shm, void *addr);
int c_isfree(meallocator *shm, int pos);
void c_occupy(meallocator *shm, int pos);

