#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

static metadata_t *head = NULL; // start of the free list

typedef struct metadata
{
    size_t size;
    struct metadata *next;
    int free; // 1 if free, 0 if allocated
} metadata_t;

metadata_t *split_block(metadata_t *block, size_t size)
{
    // Only split if there is enough space for a new header + 1 byte
    if (block->size >= size + sizeof(metadata_t) + 1)
    {
        // New free block after allocated part
        metadata_t *new_block = (metadata_t *)((char *)block + sizeof(metadata_t) + size);
        new_block->size = block->size - size - sizeof(metadata_t);
        new_block->next = block->next;
        block->size = size;
        block->next = new_block;
    }
    // do nothing if memory isn't enough to split
    block->free = 0;
    return block;
}

void coalesce()
{
    metadata_t *curr = head;
    while (curr && curr->next)
    {
        if (curr->free && curr->next->free)
        {
            // merge curr and curr->next
            curr->size += sizeof(metadata_t) + curr->next->size;
            curr->next = curr->next->next;
        }
        else
        {
            curr = curr->next;
        }
    }
}

void dfree(metadata_t *ptr)
{
    if (ptr == NULL)
    {
        return;
    }
    metadata_t *block = (metadata_t *)((char *)ptr - sizeof(metadata_t)); // cast the pointer to char* to move back exactly the size of metadata_t
    // but I think it's okay to not cast it, just use ptr - 1? since it's gonna move back by 1 metadata_t size anyway
    block->free = 1;
    coalesce();
}

void *dmalloc(size_t size)
{
    if (size <= 0)
    {
        return NULL;
    }
    metadata_t *curr = head;
    metadata_t *prev = NULL;

    size = (size + 7) & ~7; // round up to the nearest multiple of 8

    if (!head)
    { // first call
        size_t total_size = sizeof(metadata_t) + size;
        head = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (head == MAP_FAILED)
        {
            return NULL; // mmap failed
        }

        head->size = size;
        head->free = 0;
        head->next = NULL;
        return (void *)((char *)head + sizeof(metadata_t));
    }

    while (curr)
    {
        if (curr->free && curr->size >= size)
        {
            return (void *)((char *)split_block(curr, size) + sizeof(metadata_t));
        }
        curr = curr->next;
    }
    return NULL; // no suitable block found
}