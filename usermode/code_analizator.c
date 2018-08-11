#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <verificator.h>
#include "crc16.h"
#include <sqlite3.h>
#include <getopt.h>

#define VERIFICATOR "/dev/verificator"

static inline unsigned short crc16_byte(unsigned short crc, const unsigned char data)
{
	return (crc >> 8) ^ crc16_table[(crc ^ data) & 0xff];
}

unsigned short crc16(unsigned short crc, unsigned char const *buffer, size_t len)
{
	while (len--) {
		crc = crc16_byte(crc, *buffer++);
	}

	return crc;
}

static int verificator_open_device(const char *verificator)
{
	return open(verificator, O_RDWR);
}

#define verificator_open() \
	verificator_open_device(VERIFICATOR)

static void verificator_release_device(int vfd)
{
	close(vfd);
}

#define verificator_close(fd) \
	verificator_release_device(fd)

static bool verificator_verify_code(int vfd, struct verificator_verify_struct args)
{
	long ret;

	printf("Try to verify function addr[%p] size %ul crc %u\n",
		args.vrf_addr, args.vrf_size, args.hash);

	ret = ioctl(vfd, VERIFICATOR_VERIFY_CODE, &args);

	printf("ret = %u, %s\n", (unsigned short)ret, ret == args.hash ? "true" : "false");
	return ret == args.hash ? true : false;
}

#define verify_code(fd, ...)  \
	verificator_verify_code(fd, (struct verificator_verify_struct){__VA_ARGS__})

static void* verificator_get_diff(int vfd, struct verificator_get_diff_struct args)
{
	long ret;

	ret = ioctl(vfd, VERIFICATOR_GET_DIFF, &args);

	return ret != 0 ? args.vrd_code : NULL;
}

#define get_diff(fd, ...)  \
	verificator_get_diff(fd, (struct verificator_get_diff_struct){__VA_ARGS__})

static long verificator_restore(int vfd, struct verificator_restore_struct args)
{
	long ret;

	printf("Try to verify function addr[%p] size %ul code [%p]\n",
		args.vrf_addr, args.vrf_size, args.vrr_code);

	ret = ioctl(vfd, VERIFICATOR_RESTORE, &args);

	printf("ret = %u, %s\n", (unsigned short)ret, ret == 0 ? "true" : "false");

	return ret;
}

#define restore(fd, ...)  \
	verificator_restore(fd, (struct verificator_restore_struct){__VA_ARGS__})

static void print_header(int size)
{
	int i;

	for (i = 0; i < size*8; i++) {
		printf("-");
	}
	printf("\n|");
	for (i = 0; i < size*2; i++) {
		printf(" ");
	}
	printf("EXPECTED");
	for (i = 0; i < size*2 - 8; i++) {
		printf(" ");
	}
	printf("|");
	for (i = 0; i < size*2; i++) {
		printf(" ");
	}
	printf("GOTTED");
	for (i = 0; i < size*2 - 6; i++) {
		printf(" ");
	}
	printf("\n");
	for (i = 0; i < size*8; i++) {
		printf("-");
	}
}

static void print_footer(int size)
{
	int i;
	for (i = 0; i < size*8; i++) {
		printf("-");
	}
}

static void print_diff(const unsigned char *expected, const unsigned char *gotted, int size)
{
	int i, j;

	print_header(20);
	for (i = 0; i < size; i+=j) {
		int tail = size - j;

		if (tail >= 20) {
			tail = 20;
		}

		for (j = 0; j < tail; j++) {
			if (expected[i+j] != gotted[i+j]) {
				printf("!");
				printf("%02x ", expected[i+j]);
			} else {
				printf("%03x ", expected[i+j]);
			}
		}
		printf(" | ");
		for (j = 0; j < tail; j++) {
			if (expected[i+j] != gotted[i+j]) {
				printf("!");
				printf("%02x ", gotted[i+j]);
			} else {
				printf("%03x ", gotted[i+j]);
			}
		}

		printf("\n");
	}
	print_footer(20);
	printf("\n");
}

#define LINE_SIZE 20
static void print_code(const char *label, const unsigned char *code, int size)
{
	int i, j;
	printf("\n");
	print_footer(20);
	printf("\n");
	printf("%s\n", label);
	printf("\n");
	print_footer(20);
	printf("\n");

	for (i = 0; i < size; i+= j) {
		int tail = size - j;

		if (tail >= 20) {
			tail = 20;
		}

		for (j = 0; j < tail; j++) {
			printf("%02x ", code[i+j]);
		}
		printf("\n");
	}
	printf("\n");
	print_footer(20);
	printf("\n");
}

static int get_verification_list_callback(void *entry, int argc, char **argv, char **azcolname)
{
	int i;

	for (i = 0; i < argc; i++) {
		printf("|%s : %s|", azcolname[i], argv[i] ? argv[i] : "NULL");
	}
	printf("\n");

	return 0;
}

#define SQL_SELECT "SELECT * FROM verificator"
static struct verification_entry *get_verification_list(const char *bd_file)
{
	sqlite3 *db = 0;
	char *err = 0;
	int rc = 0;

	rc = sqlite3_open(bd_file, &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Ошибка открытия/создания бд - [%s]\n", sqlite3_errmsg(db));
		return NULL;
	}

	rc = sqlite3_exec(db, SQL_SELECT, get_verification_list_callback, 0, &err);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Ошибка выборки из бд - [%s]\n", sqlite3_errmsg(db));
		sqlite3_free(err);
		return NULL;
	}


	sqlite3_free(err);
	sqlite3_close(db);
	return NULL;
}

static int verify_code_callback(void *entry, int argc, char **argv, char **azcolname)
{
	unsigned long 	addr = 0;
	unsigned char 	*code;
	int 		size = 0;
	int 		vfd = *(int*)entry;
	int 		i;

	for (i = 0; i < argc; i++) {
		if (strcmp(azcolname[i], "address") == 0) {
			sscanf(argv[i], "%lx", &addr);
		} else if (strcmp(azcolname[i], "size") == 0) {
			sscanf(argv[i], "%d", &size);
		} else if (strcmp(azcolname[i], "code") == 0) {
			char *ptr;
			char *pchr;
			int j = 0;
			code = malloc(size);
			if (code == NULL) {
				fprintf(stderr, "Cannot alloc memory for code\n");
				return -1;
			}

			pchr = strtok(argv[i], " ,");
			while (pchr != NULL) {
				code[j] = (unsigned char)strtol(pchr, &ptr, 10);
				pchr = strtok(NULL, " ,");
				j++;
			}
		}

	}

	if (code == NULL || size == 0 || addr == 0) {
		printf("INVALID params code [%p] size [%d] addr [%lu]\n", code, size, addr);
		return -1;
	}

	printf("VALID params code [%p] size [%d] addr [%lu]\n", code, size, addr);
	if (!verify_code(vfd,
			.vrf_addr=addr,
			.vrf_size=size,
			.hash=crc16(0, code, size)))
	{
		printf(" Function hash is not compatible!\n");
	}

	return 0;
}

static int restore_code_callback(void *entry, int argc, char **argv, char **azcolname)
{
	unsigned long 	addr = 0;
	unsigned char 	*code;
	void 		*diff;
	int 		size = 0;
	int 		vfd = *(int*)entry;
	int		ret = 0;
	int 		i;

	for (i = 0; i < argc; i++) {
		if (strcmp(azcolname[i], "address") == 0) {
			sscanf(argv[i], "%lx", &addr);
		} else if (strcmp(azcolname[i], "size") == 0) {
			sscanf(argv[i], "%d", &size);
		} else if (strcmp(azcolname[i], "code") == 0) {
			char *ptr;
			char *pchr;
			int j = 0;
			code = malloc(size);
			if (code == NULL) {
				fprintf(stderr, "Cannot alloc memory for code\n");
				return -1;
			}

			pchr = strtok(argv[i], " ,");
			while (pchr != NULL) {
				code[j] = (unsigned char)strtol(pchr, &ptr, 10);
				pchr = strtok(NULL, " ,");
				j++;
			}
		}

	}

	if (code == NULL || size == 0 || addr == 0) {
		printf("INVALID params code [%p] size [%d] addr [%lu]\n",
							code, size, addr);
		return -1;
	}

	ret = restore(vfd, .vrf_addr=addr,
			   .vrf_size=size,
			   .vrr_code=(void*)code);
	if (ret != 0) {
		printf("Cannot restore function!\n");
		free(code);
		return -1;
	}

	return 0;
}

static int get_diff_callback(void *entry, int argc, char **argv, char **azcolname)
{
	unsigned long 	addr = 0;
	unsigned char 	*code;
	void 		*diff;
	int 		size = 0;
	int 		vfd = *(int*)entry;
	int 		i;

	for (i = 0; i < argc; i++) {
		if (strcmp(azcolname[i], "address") == 0) {
			sscanf(argv[i], "%lx", &addr);
		} else if (strcmp(azcolname[i], "size") == 0) {
			sscanf(argv[i], "%d", &size);
		} else if (strcmp(azcolname[i], "code") == 0) {
			char *ptr;
			char *pchr;
			int j = 0;
			code = malloc(size);
			if (code == NULL) {
				fprintf(stderr, "Cannot alloc memory for code\n");
				return -1;
			}

			pchr = strtok(argv[i], " ,");
			while (pchr != NULL) {
				code[j] = (unsigned char)strtol(pchr, &ptr, 10);
				pchr = strtok(NULL, " ,");
				j++;
			}
		}

	}

	if (code == NULL || size == 0 || addr == 0) {
		printf("INVALID params code [%p] size [%d] addr [%lu]\n",
							code, size, addr);
		return -1;
	}

	print_code("EXPECTED", code, size);
	diff = get_diff(vfd, .vrf_addr=addr,
			     .vrf_size=size,
			     .vrd_code=code);
	if (diff == NULL) {
		printf("Cannot get memory difference!\n");
		free(code);
		return -1;
	}

	print_code("GOTTED", code, size);

	return 0;
}

#define SQL_SELECT_WHERE_ID "SELECT * FROM verificator WHERE id=%d"
static int verificator_make_query_by_id(sqlite3 *db, int id, int vfd, int (*callback)(void *, int, char **, char **))
{
	char *sql_select_where_id;
	char *err = 0;
	int rc = 0;

	if (db == NULL || id < 0) {
		fprintf(stderr, "Невалидные параметры\n");
		return -1;
	}

	asprintf(&sql_select_where_id, SQL_SELECT_WHERE_ID, id);

	rc = sqlite3_exec(db, sql_select_where_id, callback, &vfd, &err);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Ошибка выборки из бд - [%s]\n", sqlite3_errmsg(db));
		sqlite3_free(err);
		return -1;
	}

	sqlite3_free(err);
	return 0;
}

#define SQL_SELECT_WHERE_NAME "SELECT * FROM verificator WHERE name LIKE '%s'"
static int verificator_make_query_by_name(sqlite3 *db, const char *name, int vfd, int (*callback)(void *, int, char **, char **))
{
	char *sql_select_where_name;
	char *err = 0;
	int rc = 0;

	if (db == NULL || name == NULL || name[0] == '\0') {
		fprintf(stderr, "Невалидные параметры\n");
		return -1;
	}

	asprintf(&sql_select_where_name, SQL_SELECT_WHERE_NAME, name);

	rc = sqlite3_exec(db, sql_select_where_name, callback, &vfd, &err);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Ошибка выборки из бд - [%s]\n", sqlite3_errmsg(db));
		sqlite3_free(err);
		return -1;
	}

	sqlite3_free(err);
	return 0;
}

static void test_verifying_code_by_id(void)
{
	sqlite3 *db = 0;
	char *err = 0;
	int rc = 0;
	int 	vfd;

	vfd = verificator_open();
	if (vfd < 0) {
		printf("Cannot open device! fd == %d\n", vfd);
		return;
	}

	rc = sqlite3_open("bd_verificator.bin", &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Ошибка открытия/создания бд - [%s]\n", sqlite3_errmsg(db));
		return;
	}

	verificator_make_query_by_id(db, 1, vfd, verify_code_callback);


	sqlite3_free(err);
	sqlite3_close(db);

	verificator_close(vfd);
}

static void test_get_different_code_by_id(void)
{
	sqlite3 *db = 0;
	char *err = 0;
	int rc = 0;
	int 	vfd;

	vfd = verificator_open();
	if (vfd < 0) {
		printf("Cannot open device! fd == %d\n", vfd);
		return;
	}

	rc = sqlite3_open("bd_verificator.bin", &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Ошибка открытия/создания бд - [%s]\n", sqlite3_errmsg(db));
		return;
	}

	verificator_make_query_by_id(db, 1, vfd, get_diff_callback);

	sqlite3_free(err);
	sqlite3_close(db);

	verificator_close(vfd);
}

static void test_restore_code_by_id(void)
{
	sqlite3 *db = 0;
	char *err = 0;
	int rc = 0;
	int 	vfd;

	vfd = verificator_open();
	if (vfd < 0) {
		printf("Cannot open device! fd == %d\n", vfd);
		return;
	}

	rc = sqlite3_open("bd_verificator.bin", &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Ошибка открытия/создания бд - [%s]\n", sqlite3_errmsg(db));
		return;
	}

	verificator_make_query_by_id(db, 1, vfd, restore_code_callback);

	sqlite3_free(err);
	sqlite3_close(db);

	verificator_close(vfd);
}

static void test_verifying_code_by_name(void)
{
	sqlite3 *db = 0;
	char *err = 0;
	int rc = 0;
	int 	vfd;

	vfd = verificator_open();
	if (vfd < 0) {
		printf("Cannot open device! fd == %d\n", vfd);
		return;
	}

	rc = sqlite3_open("bd_verificator.bin", &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Ошибка открытия/создания бд - [%s]\n", sqlite3_errmsg(db));
		return;
	}

	verificator_make_query_by_name(db, "do_filp_open", vfd, verify_code_callback);


	sqlite3_free(err);
	sqlite3_close(db);

	verificator_close(vfd);
}

static void test_get_different_code_by_name(void)
{
	sqlite3 *db = 0;
	char *err = 0;
	int rc = 0;
	int 	vfd;

	vfd = verificator_open();
	if (vfd < 0) {
		printf("Cannot open device! fd == %d\n", vfd);
		return;
	}

	rc = sqlite3_open("bd_verificator.bin", &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Ошибка открытия/создания бд - [%s]\n", sqlite3_errmsg(db));
		return;
	}

	verificator_make_query_by_name(db, "do_filp_open", vfd, get_diff_callback);

	sqlite3_free(err);
	sqlite3_close(db);

	verificator_close(vfd);
}

static void test_restore_code_by_name(void)
{
	sqlite3 *db = 0;
	char *err = 0;
	int rc = 0;
	int 	vfd;

	vfd = verificator_open();
	if (vfd < 0) {
		printf("Cannot open device! fd == %d\n", vfd);
		return;
	}

	rc = sqlite3_open("bd_verificator.bin", &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Ошибка открытия/создания бд - [%s]\n", sqlite3_errmsg(db));
		return;
	}

	verificator_make_query_by_name(db, "do_filp_open", vfd, restore_code_callback);

	sqlite3_free(err);
	sqlite3_close(db);

	verificator_close(vfd);
}

static void run_test(void)
{
	test_verifying_code_by_id();
	test_get_different_code_by_id();
	test_restore_code_by_id();

	test_verifying_code_by_name();
	test_get_different_code_by_name();
	test_restore_code_by_name();

}

#define DEFAULT_BD "bd_verificator.bin"
int main(int argc, const char *argv[])
{
	sqlite3 *db 		= 0;
	char 	*bd 		= DEFAULT_BD;
	char 	*err 		= 0;
	int 	verify_flag 	= 0;
	int 	diff_flag 	= 0;
	int 	restore_flag 	= 0;
	int 	id_flag 	= 0;
	char	*id_opt		= NULL;
	int 	name_flag 	= 0;
	char	*name_opt	= NULL;
	int 	list_flag 	= 0;
	int 	vfd;
	int 	rc 		= 0;
	int 	c;
	struct option verificator_options[] = {
		{"list", 0, 0, 'l'},
		{"verify", 0, 0, 'v'},
		{"diff", 0, 0, 'd'},
		{"restore", 0, 0, 'r'},
		{"id", 0, 0, 'i'},
		{"name", 0, 0, 'n'}
	};

	while ((c = getopt_long(argc, (const char **)argv, "lvdri:n:",
			&verificator_options[0], NULL)) != EOF)
	{
		switch(c) {
			case 'l':
				list_flag = 1;
				printf("l opt\n");
				break;
			case 'v':
				verify_flag = 1;
				printf("v opt\n");
				break;
			case 'd':
				diff_flag = 1;
				printf("d opt\n");
				break;
			case 'r':
				restore_flag = 1;
				printf("r opt\n");
				break;
			case 'i':
				id_flag = 1;
				if (optarg) {
					id_opt = strdup(optarg);
				}
				printf("i opt %s %s\n", id_opt, optarg);
				break;
			case 'n':
				name_flag = 1;
				if (optarg) {
					name_opt = strdup(optarg);
				}
				printf("n opt %s\n", name_opt);
				break;
			case '?':
				if (isprint (c)) {
					fprintf (stderr, "Unknown option `-%c'.\n", c);
				} else {
					fprintf(stderr, "Unknown option character `\\x%x'.\n",
					c);
				}
				return 1;
			default:
				abort();

		}
	}

	if (list_flag) {
		get_verification_list(bd);
	}

	vfd = verificator_open();
	if (vfd < 0) {
		printf("Cannot open device! fd == %d\n", vfd);
		return vfd;
	}

	rc = sqlite3_open(bd, &db);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Ошибка открытия/создания бд - [%s]\n", sqlite3_errmsg(db));
		return rc;
	}

	if (verify_flag) {
		if (id_flag && id_opt) {
			char *id_optp = id_opt;

			while (isdigit(*id_optp++));

			int len = strlen(id_opt);
			if (id_optp - id_opt == len + 1) {
				int id;
				sscanf(id_opt, "%i", &id);
				verificator_make_query_by_id(db, id, vfd, verify_code_callback);
			}
		} else if (name_flag && name_opt) {
			int len = strlen(name_opt);
			if (len > 0 && len < 255) {
				verificator_make_query_by_name(db, name_opt,
								vfd, verify_code_callback);
			}
		} else {
			fprintf(stderr, "Error! Cant verify code! Args is not correct\n");
		}
	}

	if (diff_flag) {
		if (id_flag && id_opt) {
			char *id_optp = id_opt;

			while (isdigit(*id_optp++));

			int len = strlen(id_opt);
			if (id_optp - id_opt == len + 1) {
				int id;
				sscanf(id_opt, "%i", &id);
				verificator_make_query_by_id(db, id, vfd, get_diff_callback);
			}
		} else if (name_flag && name_opt) {
			int len = strlen(name_opt);
			if (len > 0 && len < 255) {
				verificator_make_query_by_name(db, name_opt,
								vfd, get_diff_callback);
			}
		} else {
			fprintf(stderr, "Error! Cant verify code! Args is not correct\n");
		}
	}

	if (restore_flag) {
		if (id_flag && id_opt) {
			char *id_optp = id_opt;

			while (isdigit(*id_optp++));

			int len = strlen(id_opt);
			if (id_optp - id_opt == len + 1) {
				int id;
				sscanf(id_opt, "%i", &id);
				verificator_make_query_by_id(db, id, vfd, restore_code_callback);
			}
		} else if (name_flag && name_opt) {
			int len = strlen(name_opt);
			if (len > 0 && len < 255) {
				verificator_make_query_by_name(db, name_opt,
								vfd, restore_code_callback);
			}
		} else {
			fprintf(stderr, "Error! Cant verify code! Args is not correct\n");
		}
	}

	sqlite3_free(err);
	sqlite3_close(db);

	verificator_close(vfd);

	return 0;
}
