#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>

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

	spid = find_get_pid(pid);

	task = get_pid_task(spid, PIDTYPE_PID);

	// Validate inputs
	if (!task || !vaddr || !spid)
		return -EINVAL;

	mm = get_task_mm(task);
	if (!mm)
		return -ESRCH; // No memory structure for this task

	memcg = get_mem_cgroup_from_mm(mm);

	pte = get_locked_pte(mm, vaddr, &ptl);

	page = pte_page(*pte);

	// Release PTE lock
	pte_unmap_unlock(pte, ptl);

	folio = page_folio(page);

	pgdat = page_pgdat(&folio->page);

	lruvec = mem_cgroup_lruvec(memcg, pgdat);

	// Removing from current list
	lruvec_del_folio(lruvec, folio);

	// Adding to INACTIVE_FILE list
	enum lru_list lru = folio_lru_list(folio);
	update_lru_size(lruvec, LRU_INACTIVE_FILE, folio_zonenum(folio),
			folio_nr_pages(folio));
	if (lru != LRU_UNEVICTABLE)
		list_add(&folio->lru, &lruvec->lists[LRU_INACTIVE_FILE]);

	// Release the page reference
	put_page(page);

	mmput(mm);

	return 0;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_mm_kfunc_set_ids)
BTF_ID_FLAGS(func, bpf_insert_file_vaddr_into_inactive_list)
BTF_KFUNCS_END(bpf_mm_kfunc_set_ids)

// static int bpf_mm_kfuncs_filter(const struct bpf_prog *prog, u32 kfunc_id)
// {
// 	if (!btf_id_set8_contains(&bpf_mm_kfunc_set_ids, kfunc_id) ||
// 	    prog->type == BPF_PROG_TYPE_LSM)
// 		return 0;
// 	return -EACCES;
// }

static const struct btf_kfunc_id_set bpf_mm_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &bpf_mm_kfunc_set_ids,
};

static int __init bpf_mm_kfuncs_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_mm_kfunc_set);
}

late_initcall(bpf_mm_kfuncs_init);
