/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "exec_parser.h"
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

#define PERMISSION 0644
#define RET_ERR -1
#define SIG_ERROR -2
#define SUCCESS 0
#define MAX_LEN 4096

static so_exec_t *exec;
static struct sigaction old_action;
static int fd;

int found_segm(uintptr_t addr, int *found)
{
	int i, seg_index = -1;
	/**
	 * Parcurg lista de segmente pentru a gasi segmentul
	 * unde a crapat
	 */
	for (i = 0; i < exec->segments_no; i++) {
		/* E in acest segment */
		if (addr >= exec->segments[i].vaddr &&
		    addr < (exec->segments[i].vaddr +
			    exec->segments[i].mem_size)) {

			(*found) = 1;
			seg_index = i;
			break;
		}
	}

	return seg_index;
}

int alloc_data(int seg_index, int pageSize)
{
	int num_pages;

	if (exec->segments[seg_index].data == NULL) {
		/* De cate pagini am nevoie */
		if (exec->segments[seg_index].mem_size % pageSize == 0)
			num_pages =
			    exec->segments[seg_index].mem_size / pageSize;
		else
			num_pages =
			    (exec->segments[seg_index].mem_size / pageSize) + 1;

		/* Aloc vectorul de flag-uri */
		exec->segments[seg_index].data =
		    (int *)calloc(num_pages, sizeof(int));
		if (exec->segments[seg_index].data == NULL)
			return RET_ERR;
	}

	return SUCCESS;
}

int map_last_page(so_seg_t *segment, int page_index, int pageSize, int flags,
		  int seg_index, int end)
{
	int offset_page, rc, rest_to_read = 0, bytes = 0;
	char *p;
	char buffer[MAX_LEN];
	uintptr_t aux_addr;

	/* Mapez o pagina goala */
	p = mmap((void *)segment->vaddr + page_index * pageSize, pageSize,
		 PERM_W, flags | MAP_ANONYMOUS, -1, 0);
	if (p == (char *)RET_ERR)
		return RET_ERR;

	((int *)exec->segments[seg_index].data)[page_index] = 1;

	/**
	 * Trebuie copiate datele doar pana in file_size
	 * Citesc datele din buffer ca sa umplu pana in file_szie
	 */
	offset_page = segment->file_size - page_index * pageSize;
	rest_to_read = offset_page;
	rc = lseek(fd, segment->offset + page_index * pageSize, SEEK_SET);
	if (rc == RET_ERR)
		return RET_ERR;

	while (bytes < offset_page) {
		bytes += read(fd, buffer + bytes, rest_to_read);
		if (bytes == RET_ERR)
			return RET_ERR;
		rest_to_read -= bytes;
	}

	/* Copiez informatia pana in file_size si zeroizez pana la mem_size */
	aux_addr = segment->vaddr + page_index * pageSize;
	memcpy((char *)aux_addr, buffer, offset_page);
	memset((char *)aux_addr + offset_page, 0, end);

	/* Schimb permisiunile */
	rc = mprotect((void *)segment->vaddr + page_index * pageSize, pageSize,
		      segment->perm);
	if (rc == RET_ERR)
		return RET_ERR;

	return SUCCESS;
}

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	so_seg_t *segment;
	uintptr_t addr, aux_addr;
	int last_page_f, last_page_m, offset_page;
	int rc, seg_index, page_index, found = 0;
	char *p;
	int pageSize = getpagesize();
	int flags = MAP_FIXED | MAP_PRIVATE;

	/* Verific sa primesc SIGSEGV */
	if (signum != SIGSEGV) {
		old_action.sa_sigaction(signum, info, context);
		exit(RET_ERR);
	}

	/* Unde a crapat */
	addr = (uintptr_t)info->si_addr;

	seg_index = found_segm(addr, &found);

	/* Nu l-am gasit in vectorul de segmente, e seg fault */
	if (found == 0) {
		old_action.sa_sigaction(signum, info, context);
		exit(RET_ERR);
	}

	segment = &exec->segments[seg_index];

	/* Determin pe baza indexului segmentului, care e pagina */
	page_index = (addr - segment->vaddr) / pageSize;

	rc = alloc_data(seg_index, pageSize);
	if (rc != SUCCESS)
		exit(RET_ERR);

	/* Verific daca e alocata */
	if (((int *)exec->segments[seg_index].data)[page_index] == 1) {
		old_action.sa_sigaction(signum, info, context);
		exit(RET_ERR);
	}
	/* Trebuie sa o aloc */
	else {
		if (segment->file_size % pageSize == 0)
			last_page_f = segment->file_size / pageSize - 1;
		else
			last_page_f = segment->file_size / pageSize;

		if (segment->mem_size % pageSize == 0)
			last_page_m = segment->mem_size / pageSize - 1;
		else
			last_page_m = segment->mem_size / pageSize;

		if (page_index == last_page_f) {
			if (segment->file_size <= segment->mem_size) {
				if (last_page_f == last_page_m) {
					/**
					 * Mapez pana la file_size, zeroizez
					 * pana la mem_size
					 */
					rc = map_last_page(
					    segment, page_index, pageSize,
					    flags, seg_index,
					    segment->mem_size -
						segment->file_size);
					if (rc != SUCCESS)
						exit(RET_ERR);
				} else {
					/**
					 * Mapez pana la file_size, zeroizez
					 * pana la finalul paginii
					 */
					offset_page = segment->file_size -
						      page_index * pageSize;
					rc = map_last_page(
					    segment, page_index, pageSize,
					    flags, seg_index,
					    pageSize - offset_page);
					if (rc != SUCCESS)
						exit(RET_ERR);
				}
			}
		} else {
			if (page_index > last_page_f &&
			    page_index <= last_page_m) {
				/* Mapez o pagina goala */
				p = mmap((void *)segment->vaddr +
					     page_index * pageSize,
					 pageSize, PERM_W,
					 flags | MAP_ANONYMOUS, -1, 0);
				if (p == (char *)RET_ERR)
					exit(RET_ERR);

				((int *)exec->segments[seg_index]
				     .data)[page_index] = 1;

				/* Zeroizez pana la finalul paginii */
				aux_addr =
				    segment->vaddr + page_index * pageSize;
				memset((char *)aux_addr, 0, pageSize);

				rc = mprotect((void *)segment->vaddr +
						  page_index * pageSize,
					      pageSize, segment->perm);
			} else {
				p = mmap((void *)segment->vaddr +
					     page_index * pageSize,
					 pageSize, PERM_W, flags, fd,
					 segment->offset +
					     page_index * pageSize);

				if (p == (char *)RET_ERR)
					exit(RET_ERR);

				/* O setez ca alocata */
				((int *)exec->segments[seg_index]
				     .data)[page_index] = 1;

				/* Schimb permisiunile */
				rc = mprotect((void *)segment->vaddr +
						  page_index * pageSize,
					      pageSize, segment->perm);
				if (rc == RET_ERR)
					exit(RET_ERR);
			}
		}
	}
}

int so_init_loader(void)
{
	/* Initializez loader-ul */
	struct sigaction action;
	int rc;

	action.sa_sigaction = segv_handler;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	rc = sigaction(SIGSEGV, &action, &old_action);
	if (rc == RET_ERR)
		return SIG_ERROR;

	return RET_ERR;
}

int unmap_mem(void)
{
	int i, j, rc;
	int index_page_max;
	int pageSize = getpagesize();

	for (i = 0; i < exec->segments_no; i++) {
		if (exec->segments[i].mem_size % pageSize == 0)
			index_page_max = exec->segments[i].mem_size / pageSize;
		else
			index_page_max =
			    (exec->segments[i].mem_size / pageSize) + 1;
		for (j = 0; j < index_page_max; j++) {
			if (exec->segments[i].data != NULL) {
				if (((int *)exec->segments[i].data)[j] == 1) {
					rc = munmap(
					    (void *)exec->segments[i].vaddr +
						j * pageSize,
					    pageSize);
					if (rc == RET_ERR)
						return RET_ERR;
				}
			}
		}
		if (exec->segments[i].data != NULL)
			free(exec->segments[i].data);
	}

	free(exec->segments);
	free(exec);
	return SUCCESS;
}

void initialize_pages(void)
{
	int i, j, num_pages;
	int pageSize = getpagesize();

	for (i = 0; i < exec->segments_no; i++) {
		if (exec->segments[i].mem_size % pageSize == 0)
			num_pages = exec->segments[i].mem_size / pageSize;
		else
			num_pages = (exec->segments[i].mem_size / pageSize) + 1;

		for (j = 0; j < num_pages; j++)
			exec->segments[i].data = NULL;
	}
}

int so_execute(char *path, char *argv[])
{
	int err;

	/* Deschid fisierul pentru a citi datele din el */
	fd = open(path, O_RDONLY | O_CREAT, PERMISSION);
	if (fd == RET_ERR)
		return RET_ERR;

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	initialize_pages();

	so_start_exec(exec, argv);

	/* Unmap la memoria mapata */
	err = unmap_mem();
	if (err == RET_ERR)
		return RET_ERR;
	err = close(fd);
	if (err == RET_ERR)
		return RET_ERR;

	return -1;
}
