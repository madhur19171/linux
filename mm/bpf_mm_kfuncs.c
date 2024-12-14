#include "linux/list.h"
#include "linux/mm_types.h"
#include "linux/mmzone.h"
#include "linux/page-flags.h"
#include "linux/poison.h"
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/swap.h>
#include "internal.h"

#define MAX_PINNED_PAGES	(1024 * 1024)	/* Maximum number of 4KB pages that are allowed to be pinned */

int do_mlock_remote(struct mm_struct* mm, unsigned long start, size_t len, vm_flags_t flags);

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_deactivate_file_vaddr(int pid, unsigned long vaddr) {
	struct mm_struct *mm;
	struct page *page;
	struct pid *spid;
	struct task_struct *task;
	pte_t *pte;
	spinlock_t *ptl;
	struct folio *folio;
	struct mem_cgroup *memcg;
	pg_data_t *pgdat;
	enum lru_list lru;
	struct list_head *src;
	struct lruvec *lruvec;

	// Validate inputs
	if (!vaddr) {
		printk("VA is NULL\n");
		return -EINVAL;
	}

	spid = find_get_pid(pid);
	if (!spid) {
		printk("pid struct is NULL\n");
		return -EINVAL;
	}

	task = get_pid_task(spid, PIDTYPE_PID);
	if (!task) {
		printk("task struct is NULL\n");
		return -EINVAL;
	}

	mm = get_task_mm(task);
	if (!mm) {
		printk("mm struct is NULL\n");
		return -ESRCH; // No memory structure for this task
	}

	memcg = get_mem_cgroup_from_mm(mm);
	if (!memcg) {
		printk("memcg struct is NULL\n");
		return -EINVAL;
	}

	pte = get_locked_pte(mm, vaddr, &ptl);
	if (!pte) {
		printk("pte is NULL\n");
		return -EINVAL;
	}

	page = pte_page(*pte);
	if (!page) {
		printk("page is NULL\n");
		return -EINVAL;
	}

	// Release PTE lock
	pte_unmap_unlock(pte, ptl);

	folio = page_folio(page);
	if (!folio) {
		printk("folio is NULL\n");
		return -EINVAL;
	}

	pgdat = page_pgdat(&folio->page);
	if (!pgdat) {
		printk("pgdat is NULL\n");
		return -EINVAL;
	}

	lruvec = mem_cgroup_lruvec(memcg, pgdat);
	if (!lruvec) {
		printk("lruvec is NULL\n");
		return -EINVAL;
	}
	
	// Do not try to change lists if the folio is already unevictable
	if (folio_test_unevictable(folio)) {
		return 0;
	}

	folio_isolate_lru(folio);

	lruvec = folio_lruvec_lock_irq(folio);

	folio_clear_active(folio);
	folio_clear_referenced(folio);

	// Making sure that the Folio to be added again
	// is isolated. An isolated folio doesn't belong
	// to any list. Thus, it has prev and next as POISON
	if (folio->lru.next == LIST_POISON1
		&& folio->lru.prev == LIST_POISON2
		) {
		folio_clear_lru(folio);			// Remove LRU flag to prevent other threads from modifying it
		lruvec_add_folio(lruvec, folio);
		folio_set_lru(folio);			// Put the folio on LRU list
	}

	unlock_page_lruvec_irq(lruvec);
	
	return 0;
}

__bpf_kfunc int bpf_activate_file_vaddr(int pid, unsigned long vaddr) {
	struct mm_struct *mm;
	struct page *page;
	struct pid *spid;
	struct task_struct *task;
	pte_t *pte;
	spinlock_t *ptl;
	struct folio *folio;
	struct mem_cgroup *memcg;
	pg_data_t *pgdat;
	enum lru_list lru;
	struct list_head *src;
	struct lruvec *lruvec;

	// Validate inputs
	if (!vaddr) {
		printk("VA is NULL\n");
		return -EINVAL;
	}

	spid = find_get_pid(pid);
	if (!spid) {
		printk("pid struct is NULL\n");
		return -EINVAL;
	}

	task = get_pid_task(spid, PIDTYPE_PID);
	if (!task) {
		printk("task struct is NULL\n");
		return -EINVAL;
	}

	mm = get_task_mm(task);
	if (!mm) {
		printk("mm struct is NULL\n");
		return -ESRCH; // No memory structure for this task
	}

	memcg = get_mem_cgroup_from_mm(mm);
	if (!memcg) {
		printk("memcg struct is NULL\n");
		return -EINVAL;
	}

	pte = get_locked_pte(mm, vaddr, &ptl);
	if (!pte) {
		printk("pte is NULL\n");
		return -EINVAL;
	}

	page = pte_page(*pte);
	if (!page) {
		printk("page is NULL\n");
		return -EINVAL;
	}

	// Release PTE lock
	pte_unmap_unlock(pte, ptl);

	folio = page_folio(page);
	if (!folio) {
		printk("folio is NULL\n");
		return -EINVAL;
	}

	pgdat = page_pgdat(&folio->page);
	if (!pgdat) {
		printk("pgdat is NULL\n");
		return -EINVAL;
	}

	lruvec = mem_cgroup_lruvec(memcg, pgdat);
	if (!lruvec) {
		printk("lruvec is NULL\n");
		return -EINVAL;
	}

	// Do not try to change lists if the folio is already unevictable
	if (folio_test_unevictable(folio)) {
		return 0;
	}

	folio_isolate_lru(folio);
	
	lruvec = folio_lruvec_lock_irq(folio);

	folio_set_active(folio);
	folio_set_referenced(folio);

	// Making sure that the Folio to be added again
	// is isolated. An isolated folio doesn't belong
	// to any list. Thus, it has prev and next as POISON
	if (folio->lru.next == LIST_POISON1
		&& folio->lru.prev == LIST_POISON2
		) {
		folio_clear_lru(folio);			// Remove LRU flag to prevent other threads from modifying it
		lruvec_add_folio(lruvec, folio);
		folio_set_lru(folio);			// Put the folio on LRU list
	}

	unlock_page_lruvec_irq(lruvec);
	
	return 0;
}

__bpf_kfunc int bpf_pin_file_vaddr(int pid, unsigned long vaddr) {
	struct mm_struct *mm;
	struct page *page;
	// struct page page;
	// struct page *pagep = &page;
	struct pid *spid;
	struct task_struct *task;
	pte_t *pte;
	spinlock_t *ptl;
	struct folio *folio;
	struct mem_cgroup *memcg;
	pg_data_t *pgdat;
	struct lruvec *lruvec;
	enum lru_list lru;
	struct list_head *src;

	// int ret;
	// int locked = 1;

	struct vm_area_struct *vma;

	// Validate inputs
	if (!vaddr) {
		printk("VA is NULL\n");
		return -EINVAL;
	}

	spid = find_get_pid(pid);
	if (!spid) {
		printk("pid struct is NULL\n");
		return -EINVAL;
	}

	task = get_pid_task(spid, PIDTYPE_PID);
	if (!task) {
		printk("task struct is NULL\n");
		return -EINVAL;
	}

	mm = get_task_mm(task);
	if (!mm) {
		printk("mm struct is NULL\n");
		return -ESRCH; // No memory structure for this task
	}

	memcg = get_mem_cgroup_from_mm(mm);
	if (!memcg) {
		printk("memcg struct is NULL\n");
		return -EINVAL;
	}

	pte = get_locked_pte(mm, vaddr, &ptl);
	if (!pte) {
		printk("pte is NULL\n");
		return -EINVAL;
	}

	page = pte_page(*pte);
	if (!page) {
		printk("page is NULL\n");
		return -EINVAL;
	}
	
	// Release PTE lock
	pte_unmap_unlock(pte, ptl);

	folio = page_folio(page);
	if (!folio) {
		printk("folio is NULL\n");
		return -EINVAL;
	}

	pgdat = page_pgdat(&folio->page);
	if (!pgdat) {
		printk("pgdat is NULL\n");
		return -EINVAL;
	}

	lruvec = mem_cgroup_lruvec(memcg, pgdat);
	if (!lruvec) {
		printk("lruvec is NULL\n");
		return -EINVAL;
	}

	// mmap_read_lock(mm);
	// ret = pin_user_pages_remote(mm, vaddr,
	// 		     1,
	// 		     FOLL_LONGTERM | FOLL_NOFAULT,
	// 		     &pagep, &locked);
	
	// if (ret <= 0) {
	// 	printk("Failed to pin Folio for VA(0x%lx) and PID(%d)\tErrNo(%ld)\n", vaddr, pid, ret);
	// 	mmap_read_unlock(mm);
	// 	return -1;
	// } else {
	// 	printk("Pinned Folio for VA(0x%lx) and PID(%d)\n", vaddr, pid);
	// }
	// mmap_read_unlock(mm);

	// spin_lock_irq(&lruvec->lru_lock);
	// lru = folio_lru_list(folio);
	// src = &lruvec->lists[lru];
	
	// if (folio_test_unevictable(folio)) {
	// 	return 0;
	// }

	// // if (	
	// // 		folio->lru.next != NULL
	// // 		&& folio->lru.prev != NULL
	// // 		&& folio->lru.next != LIST_POISON1
	// // 		&& folio->lru.prev != LIST_POISON1
	// // 		&& folio->lru.next != LIST_POISON2
	// // 		&& folio->lru.prev != LIST_POISON2
	// // 		&& !list_empty(src) 
	// // 	) 
	// 	{		// Make sure that we are not deleting from the tail of the list or deleting an entry that is not on any list
		
	// 	// printk ("Pin Node(%p)\tPrev(%p)\tNext(%p)\n", &folio->lru, folio->lru.prev, folio->lru.next);

	// 	/* block memcg migration while the folio moves between lrus */
	// 	folio_test_clear_lru(folio);
		
	// 	lruvec_del_folio_unevictable(lruvec, folio);
	// 	folio_clear_active(folio);
	// 	folio_clear_referenced(folio);
	// 	folio_set_unevictable(folio);	// As long as I set folio unevictable, it won't be
	// 									// evicted as it is not on active or inactive list
	// 									// It doesn't really matter if the folio is on the 
	// 									// Unevictable list
	// 	lruvec_add_folio_tail (lruvec, folio);
	// }
	// spin_unlock_irq(&lruvec->lru_lock);

	if (folio_test_unevictable(folio)) {
		return 0;
	}

	folio_isolate_lru(folio);
	folio_clear_active(folio);
	folio_clear_referenced(folio);
	folio_set_unevictable(folio);

	return 0;
}

__bpf_kfunc int bpf_unpin_file_vaddr(int pid, unsigned long vaddr) {
	struct mm_struct *mm;
	struct page *page;
	struct pid *spid;
	struct task_struct *task;
	pte_t *pte;
	spinlock_t *ptl;
	struct folio *folio;
	struct mem_cgroup *memcg;
	pg_data_t *pgdat;
	struct lruvec *lruvec;
	enum lru_list lru;
	struct list_head *src;

	// Validate inputs
	if (!vaddr) {
		printk("VA is NULL\n");
		return -EINVAL;
	}

	spid = find_get_pid(pid);
	if (!spid) {
		printk("pid struct is NULL\n");
		return -EINVAL;
	}

	task = get_pid_task(spid, PIDTYPE_PID);
	if (!task) {
		printk("task struct is NULL\n");
		return -EINVAL;
	}

	mm = get_task_mm(task);
	if (!mm) {
		printk("mm struct is NULL\n");
		return -ESRCH; // No memory structure for this task
	}

	memcg = get_mem_cgroup_from_mm(mm);
	if (!memcg) {
		printk("memcg struct is NULL\n");
		return -EINVAL;
	}

	pte = get_locked_pte(mm, vaddr, &ptl);
	if (!pte) {
		printk("pte is NULL\n");
		return -EINVAL;
	}

	page = pte_page(*pte);
	if (!page) {
		printk("page is NULL\n");
		return -EINVAL;
	}
	
	// Release PTE lock
	pte_unmap_unlock(pte, ptl);

	folio = page_folio(page);
	if (!folio) {
		printk("folio is NULL\n");
		return -EINVAL;
	}

	pgdat = page_pgdat(&folio->page);
	if (!pgdat) {
		printk("pgdat is NULL\n");
		return -EINVAL;
	}

	lruvec = mem_cgroup_lruvec(memcg, pgdat);
	if (!lruvec) {
		printk("lruvec is NULL\n");
		return -EINVAL;
	}

	// lru = folio_lru_list(folio);
	// src = &lruvec->lists[lru];
	
	// if (!folio_test_unevictable(folio)) {
	// 	return 0;
	// }

	// spin_lock_irq(&lruvec->lru_lock);
	// if (	
	// 		folio->lru.next != NULL
	// 		&& folio->lru.prev != NULL
	// 		&& folio->lru.next != LIST_POISON1
	// 		&& folio->lru.prev != LIST_POISON1
	// 		&& folio->lru.next != LIST_POISON2
	// 		&& folio->lru.prev != LIST_POISON2
	// 		&& !list_empty(src)
	// 	) {		// Make sure that we are not deleting from the tail of the list
		
	// 	// printk ("Unpin Node(%p)\tPrev(%p)\tNext(%p)\n", &folio->lru, folio->lru.prev, folio->lru.next);

	// 	/* block memcg migration while the folio moves between lrus */
	// 	folio_test_clear_lru(folio);
		
	// 	// No deletion required as unevictable folio is not on any list
	// 	folio_clear_unevictable(folio);
	// 	folio_set_active(folio);
	// 	folio_set_referenced(folio);
	// 	lruvec_add_folio (lruvec, folio);
		
	// 	folio_set_lru(folio);
	// }
	// spin_unlock_irq(&lruvec->lru_lock);

	// Do not try to add on list if the folio is already unevictable
	// or already on an LRU list
	if (!folio_test_unevictable(folio) || folio_test_lru(folio)) {
		return 0;
	}

	// Making sure that the Folio to be added again
	// is isolated. An isolated folio doesn't belong
	// to any list. Thus, it has prev and next as POISON
	if (folio->lru.next == LIST_POISON1
		&& folio->lru.prev == LIST_POISON2
		) {
		struct lruvec *lruvec;

		lruvec = folio_lruvec_lock_irq(folio);
			folio_clear_unevictable(folio);	// Make folio evictable
			folio_set_active(folio);		// Activate the folio
			lruvec_add_folio(lruvec, folio);
			folio_set_lru(folio);			// Put the folio on LRU list
		unlock_page_lruvec_irq(lruvec);

		folio_put(folio);		// Decrease the ref count that was increased by isolate folio
	}

	return 0;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_mm_kfunc_set_ids)
BTF_ID_FLAGS(func, bpf_deactivate_file_vaddr)
BTF_ID_FLAGS(func, bpf_activate_file_vaddr)
BTF_ID_FLAGS(func, bpf_pin_file_vaddr)
BTF_ID_FLAGS(func, bpf_unpin_file_vaddr)
BTF_KFUNCS_END(bpf_mm_kfunc_set_ids)

static const struct btf_kfunc_id_set bpf_mm_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_mm_kfunc_set_ids,
};

static int __init bpf_mm_kfuncs_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_mm_kfunc_set);
}

late_initcall(bpf_mm_kfuncs_init);
