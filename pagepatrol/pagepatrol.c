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

// madhur's
static struct folio *get_folio(unsigned long pid, unsigned long va)
{
	struct mm_struct *mm;
	struct page *page;
	struct task_struct *task;
	pte_t *pte;
	spinlock_t *ptl;
	struct folio *folio = NULL;

	// Validate inputs
	if (!va) {
		printk("VA is NULL %ld\n", va);
		goto release;
	}

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

	pte = get_locked_pte(mm, va, &ptl);
	if (!pte) {
		printk("pte is NULL\n");
		goto release;
	}

	page = pte_page(*pte);
	if (!page) {
		printk("page is NULL\n");
		pte_unmap_unlock(pte, ptl);
		goto release;
	}

	// Release PTE lock
	pte_unmap_unlock(pte, ptl);

	folio = page_folio(page);
	if (!folio) {
		printk("folio is NULL\n");
		goto release;
	}

release:
	return folio;
}

// gianmaria's
static struct mm_struct *get_mm(unsigned long pid, unsigned long va)
{
	struct mm_struct *mm;
	struct task_struct *task;

	// Validate inputs
	if (!va) {
		printk("VA is NULL %ld\n", va);
		goto release;
	}

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

	if (mmap_read_lock_killable(mm))
		goto release;

	return mm;
release:
	return NULL;
}
static void release_mm(struct mm_struct *mm)
{
	if (!mm)
		return;
	mmap_read_unlock(mm);
}

static struct folio *get_folio2(unsigned long pid, unsigned long va)
{
	struct mm_struct *mm;
	struct page *page;
	pte_t *pte;
	struct folio *folio = NULL;

	mm = get_mm(pid, va);
	if (!mm) {
		printk("mm struct is NULL\n");
		goto release;
	}

	pte = virt_to_pte(mm, va);
	if (!pte) {
		printk("pte is NULL\n");
		goto release;
	}

	page = pte_page(*pte);
	if (!page) {
		printk("page is NULL\n");
		goto release;
	}

	folio = page_folio(page);
	if (!folio) {
		printk("folio is NULL\n");
		goto release;
	}

release:
	release_mm(mm);
	return folio;
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

static unsigned long pagepatrol_eviction_deactivate(unsigned long va)
{
	mmap_write_lock(current->mm);
	unsigned int flags = 0;
	int nr_pages = 1;
	struct page *pages[1];
	va &= PAGE_MASK;
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
	mmap_write_unlock(current->mm);
	return ret;
}

static unsigned long pagepatrol_get_list(unsigned long va)
{
	mmap_write_lock(current->mm);
	unsigned int flags = 0;
	int nr_pages = 1;
	struct page *pages[1];
	va &= PAGE_MASK;
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
	mmap_write_unlock(current->mm);
	return ret;
}

static unsigned long pagepatrol_set_list(unsigned long va, unsigned long laddr)
{
	mmap_write_lock(current->mm);
	unsigned int flags = 0;
	int nr_pages = 1;
	struct page *pages[1];
	va &= PAGE_MASK;
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
	mmap_write_unlock(current->mm);
	return ret;
}

static unsigned long pagepatrol_pin_pages(unsigned long va)
{
	mmap_write_lock(current->mm);
	unsigned int flags = FOLL_LONGTERM;
	int nr_pages = 1;
	struct page *pages[1];
	va &= PAGE_MASK;
	unsigned long ret = pin_user_pages(va, nr_pages, flags, pages);
	if (ret != 1 || !pages[0])
		ret = -EAGAIN;
	else {
		ret = (unsigned long)pages[0];
		// printk("pin %p\n", pages[0]);
	}
	//unpin_user_pages(pages, ret);
	mmap_write_unlock(current->mm);
	return ret;
}

static unsigned long pagepatrol_unpin_pages(unsigned long va,
					    unsigned long apage)
{
	mmap_write_lock(current->mm);
	struct page *pages[1];
	va &= PAGE_MASK;
	struct page *page = (struct page *)apage;
	if (page) {
		pages[0] = page;

		// pte_t *pte = virt_to_pte(current->mm, va);
		// spinlock_t *ptl;
		// pte_t *pte = get_locked_pte(current->mm, va, &ptl);
		// if (pte) {
		// 	struct page *page_p = pte_page(*pte);
		// 	if (page_p) {
		// 		if (page_p != page) {
		// 			printk("ahi ahi %p - %p - %ld - %ld\n",
		// 			       (void *)va, (void *)apage, va,
		// 			       apage);
		// 		}
		// 	}
		// }

		unpin_user_pages(pages, 1);
	}
	// int ret = get_user_pages(va, nr_pages, flags, pages);
	// if (ret != 1 || !pages[0])
	// 	ret = -EAGAIN;
	// else {
	// 	unpin_user_pages(pages, 1);
	// 	ret = 0;
	// 	// printk("pin %p\n", pages[0]);
	// }
	mmap_write_unlock(current->mm);
	return 0;
}

static unsigned long pagepatrol_eviction(unsigned long type, unsigned long va,
					 unsigned long count)
{
	switch (type) {
		/* Eviction */
	case 1:
	case 10:
	case 100:
		return pagepatrol_eviction_deactivate(va);
	/* Pinning */
	case 2:
	case 20:
		return pagepatrol_pin_pages(va);
	case 200:
		return do_mlock_pagepatrol(va, count, VM_LOCKED);
		/* User space list handling */
	case 3:
	case 30:
	case 300:
		return pagepatrol_get_list(va);
	case 4:
	case 40:
	case 400:
		return pagepatrol_set_list(va, count);
	case 5:
		return pagepatrol_unpin_pages(va, count);
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
	(void)get_folio;
	(void)get_folio2;

	return pagepatrol_eviction(type, va, count);

	// struct folio *folio = get_folio2(pid, va);
	// if (!folio) {
	// 	printk("folio is NULL\n");
	// 	return -EBADF;
	// }

	int ret = 0;

	// mmap_write_lock(current->mm);
	// folio_lock(folio);
	/*
	* see: vaddr_get_pfns
	*/
	if (type == 1 /*&& folio_test_active(folio)*/) {
		// unsigned int flags = FOLL_LONGTERM;
		// int nr_pages = 1;
		// struct page *pages[1];
		// va_or_offset &= PAGE_MASK;
		// ret = unpin_user_pages(va_or_offset, nr_pages, flags, pages);
		// if (ret != 1 || !pages[0]) {
		// 	// printk("pin user pages %ld\n", res);
		// 	goto unlock_release;
		// }

		if (va)
			ret = munlock_pagepatrol(va, count);

		struct fd f = fdget(fd);

		if (!fd_file(f))
			return -EBADF;
		vfs_fadvise(fd_file(f), (off_t)offset, count,
			    POSIX_FADV_DONTNEED);
		fdput(f);

		// mapping_evict_folio(struct address_space * mapping,
		// 		    struct folio * folio)

		// struct page *page = folio_page(folio, 0);
		// if (!page)
		// 	goto unlock_release;
		// unpin_user_pages(pages, res);

		// struct pglist_data *pgdat = folio_pgdat(folio);
		// if (!pgdat)
		// 	goto unlock_release;
		// struct lruvec *lruvec = &pgdat->__lruvec;
		// if (!lruvec)
		// 	goto unlock_release;
		// lruvec_del_folio(lruvec, folio);
		// folio_clear_active(folio);
		// folio_clear_referenced(folio);
		// folio_clear_unevictable(folio);
		// lruvec_add_folio_tail(lruvec, folio);

		// if (folio_test_active(folio))
	}
	if (type == 10) {
		mmap_write_lock(current->mm);
		unsigned int flags = 0;
		int nr_pages = 1;
		struct page *pages[1];
		va &= PAGE_MASK;
		ret = pin_user_pages(va, nr_pages, flags, pages);
		if (ret == 1 && pages[0]) {
			// printk("unpin %p\n", pages[0]);
		} else {
			ret = -EAGAIN;
		}
		unpin_user_pages(pages, ret);
		// unpin_user_pages(pages, ret);
		mmap_write_unlock(current->mm);
	}

	if (type == 100) {
		mmap_write_lock(current->mm);
		unsigned int flags = 0;
		int nr_pages = 1;
		struct page *pages[1];
		va &= PAGE_MASK;
		ret = pin_user_pages(va, nr_pages, flags, pages);
		if (ret == 1 && pages[0]) {
			struct folio *folio = page_folio(pages[0]);
			if (folio && folio_test_lru(folio)) {
				enum ttu_flags ttu_flags = TTU_BATCH_FLUSH;
				try_to_unmap(folio, ttu_flags);
				struct lruvec *lruvec = NULL;
				unsigned long flags = 0;
				folio_lruvec_relock_irqsave(folio, &lruvec,
							    &flags);
				if (lruvec) {
					lru_deactivate_file_pagepatrol(lruvec,
								       folio);
					unlock_page_lruvec_irqrestore(lruvec,
								      flags);
				}
				// deactivate_file_folio(folio);
			}
		} else {
			ret = -EAGAIN;
		}
		unpin_user_pages(pages, ret);
		// unpin_user_pages(pages, ret);
		mmap_write_unlock(current->mm);
	}

	/*
	* see: vaddr_get_pfns
	*/
	if (type == 1 /*&& !folio_test_unevictable(folio)*/) {
		// unsigned int flags = FOLL_LONGTERM;
		// int nr_pages = 1;
		// struct page *pages[1];
		// va_or_offset &= PAGE_MASK;
		// ret = pin_user_pages(va_or_offset, nr_pages, flags, pages);
		// if (ret != 1 || !pages[0]) {
		// 	// printk("pin user pages %ld\n", res);
		// 	goto unlock_release;
		// }
		ret = do_mlock_pagepatrol(va, count, VM_LOCKED);
	}
	/* 
	 * the pinning persists after the program dies,
	 * but unpinning is more difficult (cant make it to work)
	 */
	if (type == 11 /*&& !folio_test_unevictable(folio)*/) {
		mmap_write_lock(current->mm);
		unsigned int flags = FOLL_LONGTERM;
		int nr_pages = 1;
		struct page *pages[1];
		va &= PAGE_MASK;
		ret = pin_user_pages(va, nr_pages, flags, pages);
		if (ret != 1 || !pages[0])
			ret = -EAGAIN;
		else {
			// printk("pin %p\n", pages[0]);
		}
		//unpin_user_pages(pages, ret);
		mmap_write_unlock(current->mm);
	}

	if (type == 2) {
		struct fd f = fdget(fd);

		if (!fd_file(f))
			return -EBADF;
		vfs_fadvise(fd_file(f), (off_t)offset, count,
			    POSIX_FADV_WILLNEED);
		fdput(f);
	}

	if (type == 3) {
		mmap_write_lock(current->mm);
		unsigned int flags = 0;
		int nr_pages = 1;
		struct page *pages[1];
		va &= PAGE_MASK;
		ret = pin_user_pages(va, nr_pages, flags, pages);
		if (ret == 1 && pages[0]) {
			// printk("unpin %p\n", pages[0]);
			struct folio *folio = page_folio(pages[0]);
			if (folio) {
				// folio_lock(folio);
				folio_wait_writeback(folio);
				//folio_put(folio);
				// enum ttu_flags flags = TTU_BATCH_FLUSH;
				// try_to_unmap(folio, flags);
				// if (!folio_mapped(folio) &&
				//     folio_test_lru(folio)) {
				// 	//folio_unlock(folio);
				// 	folio_put(folio);
				// 	// 	// try_to_unmap_flush();
				// 	// 	struct folio_batch free_folios;
				// 	// 	folio_batch_init(&free_folios);
				// 	// 	printk("folio batch add %p\n", folio);
				// 	// 	folio_batch_add(&free_folios, folio);
				// 	// 	mem_cgroup_uncharge_folios(
				// 	// 		&free_folios);
				// 	// 	// try_to_unmap_flush();
				// 	// 	free_unref_folios(&free_folios);
				// } else {
				// 	//folio_unlock(folio);
				// }
			}
		} else {
			ret = -EAGAIN;
		}
		unpin_user_pages(pages, ret);
		// unpin_user_pages(pages, ret);
		mmap_write_unlock(current->mm);
	}

	// unlock_release:
	// folio_unlock(folio);
	return ret;
}
