#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include "internal.h"

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_insert_file_vaddr_into_inactive_list(int pid, unsigned long vaddr) {
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

	enum lru_list lru = folio_lru_list(folio);

	if (lru != LRU_UNEVICTABLE) {
		// Removing from current list
		if (folio_isolate_lru(folio)) {
			printk("Folio for VA(0x%lx) and PID(%d) Removed From Current LRU List!\n", vaddr, pid);
		}

		// Adding to INACTIVE_FILE list
		update_lru_size(lruvec, LRU_INACTIVE_FILE, folio_zonenum(folio),
				folio_nr_pages(folio));

		list_add(&folio->lru, &lruvec->lists[LRU_INACTIVE_FILE]);

		printk("Folio for VA(0x%lx) and PID(%d) Added to Inactive List!\n", vaddr, pid);
	}

	return 0;
}

__bpf_kfunc int bpf_pin_file_vaddr(int pid, unsigned long vaddr) {
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

	enum lru_list lru = folio_lru_list(folio);

	if (lru != LRU_UNEVICTABLE) {
		// Removing from current list
		if (folio_isolate_lru(folio)) {
			printk("Folio for VA(0x%lx) and PID(%d) Removed From Current LRU List!\n", vaddr, pid);
		}

		// Adding to UNEVICTABLE list
		update_lru_size(lruvec, LRU_UNEVICTABLE, folio_zonenum(folio),
				folio_nr_pages(folio));

		list_add(&folio->lru, &lruvec->lists[LRU_UNEVICTABLE]);

		printk("Folio for VA(0x%lx) and PID(%d) Added to Unevictable List!\n", vaddr, pid);
	}

	return 0;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_mm_kfunc_set_ids)
BTF_ID_FLAGS(func, bpf_insert_file_vaddr_into_inactive_list)
BTF_ID_FLAGS(func, bpf_pin_file_vaddr)
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
