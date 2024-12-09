#include <linux/kernel.h>
#include <linux/syscalls.h>

#include "../include/linux/mm_inline.h"
#include "../include/linux/memcontrol.h"
#include "../include/linux/pagewalk.h"
#include "../mm/internal.h"
#include "../include/uapi/linux/fadvise.h"

static pte_t *virt_to_pte(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	if (mm == NULL)
		return NULL;

	pgd = pgd_offset(mm, addr);
	if (!pgd || !pgd_present(*pgd))
		return NULL;

	p4d = p4d_offset(pgd, addr);
	if (!p4d || !p4d_present(*p4d))
		return NULL;

	pud = pud_offset(p4d, addr);
	if (!pud || !pud_present(*pud))
		return NULL;

	pmd = pmd_offset(pud, addr);
	if (!pmd || !pmd_present(*pmd))
		return NULL;

	return pte_offset_kernel(pmd, addr);
}

// gianmaria's
static struct mm_struct *get_mm(unsigned long pid)
{
	struct mm_struct *mm;
	struct task_struct *task;

	task = find_task_by_vpid(pid);
	if (!task) {
		printk("task struct is NULL\n");
		goto release;
	}

	mm = get_task_mm(task);
	if (!mm) {
		printk("mm struct is NULL\n");
		goto release;
	}

	return mm;
release:
	return NULL;
}

static unsigned long lru_deactivate_file_pagepatrol(struct lruvec *lruvec,
						    struct folio *folio)
{
	bool active = folio_test_active(folio);
	long nr_pages = folio_nr_pages(folio);

	if (folio_test_unevictable(folio))
		return 1;

	/* Some processes are using the folio */
	if (folio_mapped(folio))
		return 1;

	lruvec_del_folio(lruvec, folio);
	folio_clear_active(folio);
	folio_clear_referenced(folio);

	lruvec_add_folio_tail(lruvec, folio);
	folio_set_reclaim(folio);
	__count_vm_events(PGROTATED, nr_pages);

	if (active) {
		__count_vm_events(PGDEACTIVATE, nr_pages);
		__count_memcg_events(lruvec_memcg(lruvec), PGDEACTIVATE,
				     nr_pages);
	}

	return 0;
}

static unsigned long pagepatrol_eviction_deactivate(struct mm_struct *mm,
						    unsigned long va)
{
	if (!mm)
		return -EAGAIN;
	// mmap_write_lock(current->mm);
	mmap_write_lock(mm);
	unsigned int flags = 0;
	int nr_pages = 1;
	struct page *pages[1];
	unsigned long ret = pin_user_pages(va, nr_pages, flags, pages);
	if (ret == 1 && pages[0]) {
		struct folio *folio = page_folio(pages[0]);
		int vret = 0;
		if (folio && folio_test_lru(folio)) {
			enum ttu_flags ttu_flags = TTU_BATCH_FLUSH;
			try_to_unmap(folio, ttu_flags);
			try_to_unmap_flush();
			struct lruvec *lruvec = NULL;
			unsigned long flags = 0;
			folio_lruvec_relock_irqsave(folio, &lruvec, &flags);
			if (lruvec) {
				vret = lru_deactivate_file_pagepatrol(lruvec,
								      folio);
				unlock_page_lruvec_irqrestore(lruvec, flags);
			}
			// deactivate_file_folio(folio);
		}
		unpin_user_pages(pages, ret);
		ret = vret;
	} else {
		ret = -EAGAIN;
	}
	// mmap_write_unlock(current->mm);
	mmap_write_unlock(mm);
	return ret;
}

static unsigned long pagepatrol_get_list(struct mm_struct *mm, unsigned long va)
{
	if (!mm)
		return -EAGAIN;
	// mmap_write_lock(current->mm);
	mmap_write_lock(mm);
	unsigned int flags = 0;
	int nr_pages = 1;
	struct page *pages[1];
	unsigned long ret = pin_user_pages(va, nr_pages, flags, pages);
	if (ret == 1 && pages[0]) {
		struct folio *folio = page_folio(pages[0]);
		unsigned long vret = 0;
		if (folio && folio_test_lru(folio)) {
			vret = folio->pp_list;
		}
		unpin_user_pages(pages, ret);
		ret = vret;
	} else {
		ret = -EAGAIN;
	}
	mmap_write_unlock(mm);
	return ret;
}

static unsigned long pagepatrol_set_list(struct mm_struct *mm, unsigned long va,
					 unsigned long laddr)
{
	if (!mm)
		return -EAGAIN;
	// mmap_write_lock(current->mm);
	mmap_write_lock(mm);
	unsigned int flags = 0;
	int nr_pages = 1;
	struct page *pages[1];
	unsigned long ret = pin_user_pages(va, nr_pages, flags, pages);
	if (ret == 1 && pages[0]) {
		struct folio *folio = page_folio(pages[0]);
		if (folio && folio_test_lru(folio)) {
			folio->pp_list = laddr;
		}
		unpin_user_pages(pages, ret);
		ret = 0;
	} else {
		ret = -EAGAIN;
	}
	mmap_write_unlock(mm);
	return ret;
}

static unsigned long pagepatrol_pin_pages(struct mm_struct *mm,
					  unsigned long va)
{
	if (!mm)
		return -EAGAIN;
	// mmap_write_lock(current->mm);
	mmap_write_lock(mm);
	unsigned int flags = FOLL_LONGTERM;
	int nr_pages = 1;
	struct page *pages[1];
	unsigned long ret = pin_user_pages(va, nr_pages, flags, pages);
	if (ret != 1 || !pages[0])
		ret = -EAGAIN;
	else {
		ret = (unsigned long)pages[0];
		// printk("pin %p\n", pages[0]);
	}
	mmap_write_unlock(mm);
	return ret;
}

static unsigned long pagepatrol_unpin_pages(struct mm_struct *mm,
					    unsigned long va,
					    unsigned long apage)
{
	if (!mm)
		return -EAGAIN;
	// mmap_write_lock(current->mm);
	mmap_write_lock(mm);
	struct page *pages[1];
	va &= PAGE_MASK;
	struct page *page = (struct page *)apage;
	if (page) {
		pages[0] = page;
		unpin_user_pages(pages, 1);
	}
	mmap_write_unlock(mm);
	return 0;
}

static unsigned long pagepatrol_eviction(unsigned long pid, unsigned long type,
					 unsigned long va, unsigned long count)
{
	struct mm_struct *mm = get_mm(pid);
	if (!mm)
		return -EAGAIN;
	if (current->mm != mm) {
		printk("they are different %p - %p\n", current->mm, mm);
	}
	switch (type) {
		/* Eviction */
	case 1:
	case 10:
	case 100:
		return pagepatrol_eviction_deactivate(mm, va);
	/* Pinning */
	case 2:
	case 20:
		return pagepatrol_pin_pages(mm, va);
	case 200:
		return do_mlock_pagepatrol(va, count, VM_LOCKED);
		/* User space list handling */
	case 3:
	case 30:
	case 300:
		return pagepatrol_get_list(mm, va);
	case 4:
	case 40:
	case 400:
		return pagepatrol_set_list(mm, va, count);
	/* Unpinning */
	case 5:
		return pagepatrol_unpin_pages(mm, va, count);
	}

	return -EAGAIN;
}

/*
 * read this 
 * https://blogs.oracle.com/linux/post/pinning-userspace-pages-in-the-linux-kernel
 */
SYSCALL_DEFINE6(hello, unsigned long, pid, unsigned long, fd, unsigned long, va,
		unsigned long, offset, unsigned long, count, unsigned long,
		type)
{
	/* maybe we need it */
	(void)virt_to_pte;
	return pagepatrol_eviction(pid, type, va &= PAGE_MASK, count);
}
