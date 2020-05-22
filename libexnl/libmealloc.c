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


//#define DEBUG
#include "include/libmealloc.h"

shared_buffers *sbuff_init(){
	shared_buffers *b;
	int i;

	DODEBUG("mealloc.sbuff_init - get shared memory\n");
	b = (shared_buffers *) mmap(NULL, sizeof(b) , PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (b==NULL) return b;
	DODEBUG("mealloc.sbuff_init - init struct & semaphore\n");
	sem_init(&b->semaphore, 0, 7);

	sem_getvalue(&b->semaphore, &i);
	DODEBUG("mealloc.get_sbuff - semaphore from current value %d\n", i);

	b->map=0;
	b->busy=0;
	DODEBUG("mealloc.sbuff_init - zeroing %d bytes %p in matrioska @%p \n", BUF_NUM*BUF_SIZE, b->buffzone, b);
	memset(b->buffzone, 0, BUF_NUM*BUF_SIZE );
	return b;
}

void *get_sbuff(shared_buffers *b){
	int i=0;

	DODEBUG("mealloc.get_sbuff - wait busy entities to release this resource\n");
	while (b->busy==1);
	sem_wait(&b->semaphore);
	b->busy=1;
	while (i<BUF_NUM) {
		DODEBUG("mealloc.get_sbuff - iteration %d mask 0x%02x\n", i, (1<<i));
		if ((b->map & (1<<i))!=(1<<i)) {
			DODEBUG("mealloc.get_sbuff - fist free is number %d\n", i);
			b->busy=0;
			b->map|=(1<<i);
			return (void *) (((char *) b->buffzone)+(BUF_SIZE*i));
			}
		i++;
		}
	DODEBUG("mealloc.get_sbuff - no fee found :(\n");
	b->busy=0;
	return NULL;
}

void rel_sbuf(shared_buffers *b, void *addr){
	DODEBUG("mealloc.rel_sbuf - request to release buffer.given data is  b=%p and addr=%p.  buffsize=%x (int) ( addr - ((void *) (b->buffzone)) )=%x\n",  b, addr, BUF_SIZE, (int) ( addr - ((void *) (b->buffzone)) ));
	int i= (int) ( addr - ((void *) (b->buffzone)) ) / BUF_SIZE;
	DODEBUG("mealloc.rel_sbuf - request to release buffer number %d. Calculated mask is 0x%02x\n", i, ~(1<<i));
	b->map&=(~(1<<i));
	sem_post(&b->semaphore);
}

void sbuff_destroy(shared_buffers *b){
	 munmap(b, sizeof(b));

}

void *mealloc_init(uint32_t reserved, uint32_t generic_element_size){
	void *tmp;

	DODEBUG("mealloc.mealloc_init - arguments: reserved=%d, generic_element_size=%d\n", reserved, generic_element_size );
	DODEBUG("mealloc.mealloc_init - mmap for %ld of shared memory\n", SHM_SIZE(reserved, generic_element_size, CELLS_NUMBER ));
	tmp = mmap(NULL, SHM_SIZE(reserved, generic_element_size, CELLS_NUMBER ), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	DODEBUG("mealloc.mealloc_init - Zeroing %ld bytes @%p \n", SHM_SIZE(reserved, generic_element_size, CELLS_NUMBER ), tmp);
	memset(tmp, 0, SHM_SIZE(reserved, generic_element_size, CELLS_NUMBER ) );
	((meallocator *)tmp)->generic_element_size=generic_element_size;
	((meallocator *)tmp)->reserved=reserved;
	return tmp;
}

void mealloc_destroy(void *shm){
	DODEBUG("mealloc.mealloc_destroy - shared memory @%p is no more\n", shm );
	munmap(shm, SHM_SIZE(((meallocator *)shm)->reserved, ((meallocator *)shm)->generic_element_size, CELLS_NUMBER ));
}
void *get_reserved_addr(void *shm){
	return ((void *)((char *) shm)+ sizeof(meallocator) );
}

void *mealloc(void *shm){
	int i;

	DODEBUG("mealloc.mealloc - find first free element\n");
	for (i=0; i<CELLS_NUMBER; i++) {
		DODEBUG("mealloc.mealloc - consider %d\n", i );
		if (c_isfree(shm, i)==ISFREE) {
			DODEBUG("mealloc.mealloc - found element %d is free\n", i );
			c_occupy(shm, i);
			return ((void *)((char *) shm)+ SHM_NTH_EL_ADDR(((meallocator *)shm)->reserved, ((meallocator *)shm)->generic_element_size, i));
			}
		}
	return NULL;
}

void mefree(meallocator *shm, void *addr){
	DODEBUG("mealloc.mefree - request to free addr@%p, base@%p\n", shm, addr);
	c_free(shm, addr);
	DODEBUG("mealloc.mefree - erase content\n");
	memset(addr, 0, shm->generic_element_size);
}

void c_free(meallocator *shm, void *addr){
	DODEBUG("mealloc.c_free - request to free addr@%p, base@%p\n", shm, addr);
	int pos=(((int) ( ((char *) addr)-((char *) shm))) - sizeof(meallocator) - shm->reserved)/shm->generic_element_size;
	DODEBUG("mealloc.c_free - element is number %d\n", pos);
	shm->map[pos>>5] &= !(1 << (pos &0x1f));
}

int c_isfree(meallocator *shm, int pos){
	DODEBUG("mealloc.c_isfree - request to check element %d, element is in %d uint32\n", pos, pos>>5);
	DODEBUG("mealloc.c_isfree - shm->map[%d]=0x%08x, masked with 0x%08x\n", pos>>5, shm->map[pos>>5], (1 << (pos &0x1f)));
	DODEBUG("mealloc.c_isfree - isfree test (0x%08x & 0x%08x )=0x%08x\n", shm->map[pos>>5], (1 << (pos &0x1f)), (shm->map[pos>>5] & (1 << (pos &0x1f))) );
	return ((shm->map[pos>>5] & (1 << (pos &0x1f)))!=0)?ISBUSY:ISFREE;
}

void c_occupy(meallocator *shm, int pos){
	DODEBUG("mealloc.c_occupy - request to reserve element %d, element is in %d uint32\n", pos, pos>>5);
	DODEBUG("mealloc.c_occupy - shm->map[%d]=0x%08x, masked with 0x%08x\n", pos>>5, shm->map[pos>>5], (1 << (pos &0x1f)));
	shm->map[pos>>5] |= (1 << (pos &0x1f)) ;
}
