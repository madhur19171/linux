#ifndef	_LINUX_PLAINLIST_H
#define	_LINUX_PLAINLIST_H

#include "linux/gfp_types.h"
#include "linux/slab.h"
#include <linux/container_of.h>

#include <linux/stddef.h>
#include <linux/rcupdate.h>

#define MAX_PLAIN_LIST_SIZE		0x10000		/* 64K nodes */
#define PAGE_OFFSET_BITS		12

struct pl_node {
	void *opaque;							// Holds IOVA when used in IOVA allocator
	unsigned long frame_number		: 52;	// Generic frame number. Can be physical (PFN) or virtual (VFN)
	struct pl_flags {
		unsigned long valid			: 1;	// Valid bit for the node
		unsigned long range_start	: 1;	// This node is the start of an IOVA range
		unsigned long range_end		: 1;	// This node is the end of a range
		unsigned long resvd			: 9;	// Reserved bits for the node
	} pl_flags;
};

struct plain_list {
	unsigned long base;		// Base frame of the plain list
							// actual frame_number of any pl_node is (base + pl_node->frame_number
	struct pl_node pl_root_node[MAX_PLAIN_LIST_SIZE];
};

// Initialize the Plain List to be empty and with a valid base node
static __always_inline
struct plain_list * init_pl (unsigned long base) {
	struct plain_list * plain_list;

	plain_list = kzalloc(sizeof(struct plain_list), GFP_KERNEL);

	plain_list->base = base;

	for (int i = 0; i < MAX_PLAIN_LIST_SIZE; i++) {
		plain_list->pl_root_node[i].opaque					= NULL;
		plain_list->pl_root_node[i].pl_flags.valid			= 0;	// Invalidate the nodes
		plain_list->pl_root_node[i].pl_flags.range_start	= 0;
		plain_list->pl_root_node[i].pl_flags.range_end		= 0;
		plain_list->pl_root_node[i].frame_number			= i;	// Initialize the frame numbers
	}

	return plain_list;
}

static __always_inline
struct pl_node * allocate_pl_node (struct plain_list * plain_list, unsigned long num) {
	struct pl_node * pl_node = NULL;
	int i = 0;
	bool contig = true;

	for (; i < MAX_PLAIN_LIST_SIZE - num; i++) {
		if (plain_list->pl_root_node[i].pl_flags.valid == 0) {	// Unallocated node
			for (int j = 0; j < num; j++) {
				contig &= plain_list->pl_root_node[i + j].pl_flags.valid == 0;
			}
		}

		if (contig) break;
	}

	if (i < MAX_PLAIN_LIST_SIZE - num) {
		for (int j = 0; j < num; j++) {
			plain_list->pl_root_node[i + j].pl_flags.valid = 1;
			plain_list->pl_root_node[i + j].pl_flags.range_start = 0;
			plain_list->pl_root_node[i + j].pl_flags.range_end = 0;
		}

		plain_list->pl_root_node[i + num - 1].pl_flags.range_end = 1;
		pl_node = &plain_list->pl_root_node[i];
		pl_node->pl_flags.range_start = 1;	// First node starts the range
	}

	// If NULL is returned, there were no free nodes to be allocated
	return pl_node;
}

// Returns the opaque pointer stored in the start node of the range
static __always_inline
void * free_pl_node (struct plain_list * plain_list, unsigned long frame_number) {
	unsigned long start_node_number = frame_number;
	unsigned long end_node_number = frame_number;

	while (start_node_number != 0 && plain_list->pl_root_node[start_node_number].pl_flags.range_start == 0) {
		plain_list->pl_root_node[start_node_number].pl_flags.valid = 0;		// Deallocate all nodes left 
																			// of the pl_node in the range in which pl_node resides
		start_node_number--;
	}

	while (end_node_number != (MAX_PLAIN_LIST_SIZE - 1) && plain_list->pl_root_node[end_node_number].pl_flags.range_end == 0) {
		plain_list->pl_root_node[end_node_number].pl_flags.valid = 0;		// Deallocate all nodes right 
																			// of the pl_node in the range in which pl_node resides
		end_node_number++;
	}

	// Demark and deallocate the range extremes
	plain_list->pl_root_node[start_node_number].pl_flags.valid = 0;
	plain_list->pl_root_node[start_node_number].pl_flags.range_start = 0;
	plain_list->pl_root_node[end_node_number].pl_flags.valid = 0;
	plain_list->pl_root_node[end_node_number].pl_flags.range_end = 0;

	return plain_list->pl_root_node[start_node_number].opaque;
}

#endif	/* _LINUX_PLAINLIST_H */
