/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */

#include <stdio.h>
#include <Windows.h>

#define DLL_EXPORTS
#include "loader.h"
#include "exec_parser.h"

#define SEG_ERROR_FAULT 139
#define RET_ERR -1
#define SIG_ERROR -2
#define SUCCESS 0
#define MAX_LEN 0x10000

static so_exec_t *exec;
static HANDLE fd;
static int pageSize = 0x10000;
static LPVOID access_violation_handler;
static LPBYTE p;

int found_permissions(so_seg_t *segment)
{
	/**
	 * Alege flag-ul corespunzator pentru
	 * VirtualAlloc, in functie de permisiunile
	 * din acel segment
	 */
	if (segment->perm == PERM_R)
		return PAGE_READONLY;
	else if (segment->perm == PERM_W)
		return PAGE_WRITECOPY;
	else if (segment->perm == PERM_X)
		return PAGE_EXECUTE;
	else if (segment->perm == (PERM_R | PERM_W))
		return PAGE_READWRITE;
	else if (segment->perm == (PERM_R | PERM_X))
		return PAGE_EXECUTE_READ;
	else if (segment->perm == (PERM_W | PERM_X))
		return PAGE_EXECUTE_WRITECOPY;
	else
		return PAGE_EXECUTE_READWRITE;
}

int found_segm(uintptr_t addr, int *found)
{
	int i, seg_index = -1;
	/**
	 * Parcurg lista de segmente pentru a gasi segmentul
	 * unde se primeste seg_fault
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

int map_page(so_seg_t *segment, int page_index, int offset, int seg_index)
{
	char *p;
	int permissions, rest_to_read, rc, bytes = 0;
	char buffer[MAX_LEN];
	DWORD old;
	uintptr_t aux_addr;

	/* Aloc o pagina goala */
	p = VirtualAlloc((LPVOID) (segment->vaddr +
		page_index * pageSize), pageSize, MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	if (p == NULL)
		exit(SEG_ERROR_FAULT);

	/* Citesc din file offset bytes */
	rest_to_read = offset;
	rc = SetFilePointer(fd, segment->offset + page_index * pageSize,
		NULL, SEEK_SET);

	if (rc == INVALID_SET_FILE_POINTER)
		return RET_ERR;

	while (bytes < offset) {
		rc = ReadFile(fd, buffer + bytes, rest_to_read, &bytes, NULL);
		if (rc == 0)
			return RET_ERR;

		rest_to_read -= bytes;
	}

	/* Copiez informatia de pana in offset in memorie */
	aux_addr = segment->vaddr + page_index * pageSize;
	memcpy((char *)aux_addr, buffer, offset);

	/* O setez ca alocata */
	((int *)exec->segments[seg_index]
			.data)[page_index] = 1;

	/* Schimb permisiunile */
	permissions = found_permissions(segment);
	rc = VirtualProtect((LPVOID) (segment->vaddr +
			page_index * pageSize), pageSize, permissions, &old);
	if (rc == FALSE)
		exit(SEG_ERROR_FAULT);

	return SUCCESS;
}

static LONG CALLBACK segv_handler(PEXCEPTION_POINTERS ExceptionInfo)
{
	so_seg_t *segment;
	LPBYTE addr;
	uintptr_t aux_addr;
	int offset, last_page_f, last_page_m;
	int rc, seg_index, page_index, found = 0;
	char *p;

	/* Unde s-a obtinut seg_fault */
	addr = (LPBYTE)ExceptionInfo->ExceptionRecord->ExceptionInformation[1];

	seg_index = found_segm((uintptr_t) addr, &found);

	/* Nu l-am gasit in vectorul de segmente, e seg fault */
	if (found == 0)
		exit(SEG_ERROR_FAULT);

	segment = &exec->segments[seg_index];

	/* Determin pe baza indexului segmentului, care e pagina */
	page_index = (int) (addr - segment->vaddr) / pageSize;

	/* Aloc vectorul de flag-uri pentru pagini alocate */
	rc = alloc_data(seg_index, pageSize);
	if (rc != SUCCESS)
		exit(SEG_ERROR_FAULT);

	/* Verific daca e alocata */
	if (((int *)exec->segments[seg_index].data)[page_index] == 1)
		exit(SEG_ERROR_FAULT);
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

		/* Sunt in ultima pagina din segment */
		if (page_index == last_page_f) {
			offset = segment->file_size - pageSize * page_index;
			rc = map_page(segment, page_index, offset, seg_index);
			if (rc != SUCCESS)
				return rc;
		} else {
			/**
			 * Sunt pe paginile dintre file_size si
			 * mem_size, trebuie sa mapez pagini goale
			 */
			if ((page_index > last_page_f &&
			    page_index <= last_page_m) ||
				(page_index <= last_page_f &&
			    page_index > last_page_m)) {
				/* Mapez o pagina goala */
				p = VirtualAlloc((LPVOID) (segment->vaddr +
					page_index * pageSize), pageSize,
					MEM_COMMIT | MEM_RESERVE,
					PAGE_READWRITE);
				if (p == NULL)
					exit(SEG_ERROR_FAULT);

				((int *)exec->segments[seg_index]
				     .data)[page_index] = 1;

				/* Zeroizez pana la finalul paginii */
				aux_addr =
				    segment->vaddr + page_index * pageSize;
				memset((char *)aux_addr, 0, pageSize);
			} else {
			/* Citesc din fisier o pagina si o mapez in memorie */
			rc = map_page(segment, page_index, pageSize, seg_index);
			if (rc != SUCCESS)
				return rc;
			}
		}
	}

	return EXCEPTION_CONTINUE_EXECUTION;
}

int so_init_loader(void)
{
	/* Initializez loader-ul */
	access_violation_handler = AddVectoredExceptionHandler(1,
							segv_handler);

	if (access_violation_handler == NULL)
		return SIG_ERROR;

	return RET_ERR;
}

int unmap_mem(void)
{
	int i, j, rc;
	int index_page_max;

	/* Fac unmap la paginile alocate */
	for (i = 0; i < exec->segments_no; i++) {
		if (exec->segments[i].mem_size % pageSize == 0)
			index_page_max = exec->segments[i].mem_size / pageSize;
		else
			index_page_max =
			    (exec->segments[i].mem_size / pageSize) + 1;
		for (j = 0; j < index_page_max; j++) {
			if (exec->segments[i].data != NULL) {
				if (((int *)exec->segments[i].data)[j] == 1) {
					rc = VirtualFree(
					(LPVOID)(exec->segments[i].vaddr +
					j * pageSize), pageSize, MEM_DECOMMIT);
					if (rc == FALSE)
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

	/**
	 * Initializez vectorul de flag-uri folosit
	 * paginile alocate cu NULL
	 */
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
	long access, share, disposition;

	access = GENERIC_READ;
	share = FILE_SHARE_READ | FILE_SHARE_WRITE;
	disposition = OPEN_EXISTING;

	/* Deschid fisierul pentru a citi datele din el */
	fd = CreateFile(path, access, share, NULL, disposition,
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (fd == INVALID_HANDLE_VALUE)
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

	err = CloseHandle(fd);
	if (err == 0)
		return RET_ERR;

	return -1;
}
