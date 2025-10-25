#include <stdio.h>  // needed for size_t etc.
#include <unistd.h> // needed for sbrk etc.
#include <sys/mman.h> // needed for mmap
#include <assert.h> // needed for asserts
#include "dmm.h"

/* 
 * The lab handout and code guide you to a solution with a single free list containing all free
 * blocks (and only the blocks that are free) sorted by starting address.  Every block (allocated
 * or free) has a header (type metadata_t) with list pointers, but no footers are defined.
 * That solution is "simple" but inefficient.  You can improve it using the concepts from the
 * reading.
 */

/* 
 *size_t is the return type of the sizeof operator.   size_t type is large enough to represent
 * the size of the largest possible object (equivalently, the maximum virtual address).
 */

typedef struct metadata {
  size_t size;
  struct metadata* next;
  struct metadata* prev;
} metadata_t;

/*
 * Head of the freelist: pointer to the header of the first free block.
 */

static metadata_t* freelist = NULL; // initiated freelist to NULL

static void remove_from_freelist(metadata_t *block) {
  if (!block) return;
  if (block->prev) block->prev->next = block->next;
  else freelist = block->next; // was head
  if (block->next) block->next->prev = block->prev;
  block->next = block->prev = NULL;
}

static void insert_sorted_freelist(metadata_t *block) {
    metadata_t *curr = freelist;
    metadata_t *prev = NULL;

    /* find insertion point (first node with address > block) */
    while (curr && curr < block) {
        prev = curr;
        curr = curr->next;
    }

    block->next = curr;
    block->prev = prev;
    if (curr) curr->prev = block;
    if (prev) prev->next = block;
    else freelist = block;
}

static metadata_t* coalesce_block(metadata_t *block) {
    if (!block) return NULL;

    // merge forward
    if (block->next && (char*)block + METADATA_T_ALIGNED + block->size == (char*)block->next) {
        metadata_t *next = block->next;
        block->size += METADATA_T_ALIGNED + next->size;
        block->next = next->next;
        if (next->next) next->next->prev = block;
    }

    // merge backward
    if (block->prev && (char*)block->prev + METADATA_T_ALIGNED + block->prev->size == (char*)block) {
        metadata_t *prev = block->prev;
        prev->size += METADATA_T_ALIGNED + block->size;
        prev->next = block->next;
        if (block->next) block->next->prev = prev;
        block = prev;
    }

    return block;
}


static metadata_t* split_block_for_alloc(metadata_t *block, size_t size) {
    assert(block != NULL);
    if (block->size >= size + METADATA_T_ALIGNED + 1) {
        // new free block lives after allocated prefix
        remove_from_freelist(block);
         metadata_t *new_block = (metadata_t*)((char*)block + METADATA_T_ALIGNED + size);
        new_block->size = block->size - size - METADATA_T_ALIGNED;
        new_block->next = new_block->prev = NULL;

        // insert remainder back
        insert_sorted_freelist(new_block);

        block->size = size;
        block->next = block->prev = NULL;
        return block;
    } else {
        remove_from_freelist(block);
        return block;
    }
}

void* dmalloc(size_t numbytes) {
  if(freelist == NULL) {
    if(!dmalloc_init()) {
      return NULL;
    }
  }
  assert(numbytes > 0);
  /* your code here */
numbytes = ALIGN(numbytes);

    // first-fit through freelist (which is address-sorted)
    metadata_t *curr = freelist;
    while (curr) {
        if (curr->size >= numbytes) {
            // found a free block; split if possible and remove allocated prefix from freelist
            metadata_t *alloc_block = split_block_for_alloc(curr, numbytes);
            // return pointer to payload
            return (void*)((char*)alloc_block + METADATA_T_ALIGNED);
        }
        curr = curr->next;
    }
    // no suitable block found 
  return NULL;
}

void dfree(void* ptr) {
  /* your code here */
  if (!ptr) return;
  metadata_t *block = (metadata_t*)((char*)ptr - METADATA_T_ALIGNED);
  insert_sorted_freelist(block);
  metadata_t *merged = coalesce_block(block);
  (void)merged;
}

/*
 * Allocate heap_region slab with a suitable syscall.
 */
bool dmalloc_init() {

  size_t max_bytes = ALIGN(MAX_HEAP_SIZE);

  /*
   * Get a slab with mmap, and put it on the freelist as one large block, starting
   * with an empty header.
   */
  freelist = (metadata_t*)
     mmap(NULL, max_bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (freelist == (void *)-1) {
    perror("dmalloc_init: mmap failed");
    return false;
  }
  freelist->next = NULL;
  freelist->prev = NULL;
  freelist->size = max_bytes-METADATA_T_ALIGNED;
  return true;
}


/* for debugging; can be turned off through -NDEBUG flag*/
/*

This code is here for reference.  It may be useful.
Warning: the NDEBUG flag also turns off assert protection.


void print_freelist(); 

#ifdef NDEBUG
	#define DEBUG(M, ...)
	#define PRINT_FREELIST print_freelist
#else
	#define DEBUG(M, ...) fprintf(stderr, "[DEBUG] %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
	#define PRINT_FREELIST
#endif


void print_freelist() {
  metadata_t *freelist_head = freelist;
  while(freelist_head != NULL) {
    DEBUG("\tFreelist Size:%zd, Head:%p, Prev:%p, Next:%p\t",
	  freelist_head->size,
	  freelist_head,
	  freelist_head->prev,
	  freelist_head->next);
    freelist_head = freelist_head->next;
  }
  DEBUG("\n");
}
*/
