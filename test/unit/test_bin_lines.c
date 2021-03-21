// SPDX-FileCopyrightText: 2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "minunit.h"

bool test_source_line_info_builder_empty() {
	RzBinSourceLineInfoBuilder bob;
	rz_bin_source_line_info_builder_init(&bob);
	// add nothing
	RzBinSourceLineInfo *li = rz_bin_source_line_info_builder_build_and_fini(&bob);
	mu_assert_eq(li->files_count, 0, "files count");
	mu_assert_null(li->files, "files");
	mu_assert_eq(li->lines_count, 0, "lines count");
	mu_assert_null(li->lines, "lines");
	rz_bin_source_line_info_free(li);
	mu_end;
}

#define FUZZ_COUNT 200

bool test_source_line_info_builder() {
	for (size_t f = 0; f < FUZZ_COUNT; f++) {
		RzBinSourceLineInfoBuilder bob;
		rz_bin_source_line_info_builder_init(&bob);

		// push the samples in random orders
#define SAMPLES_COUNT 18
		bool samples_applied[SAMPLES_COUNT] = { 0 };
		for (size_t i = 0; i < SAMPLES_COUNT; i++) {
			size_t j = rand() % SAMPLES_COUNT;
			while (samples_applied[j]) {
				j = (j + 1) % SAMPLES_COUNT;
			}
#undef SAMPLES_COUNT
			samples_applied[j] = true;
			switch (j) {
			case 0:
				rz_bin_source_line_info_builder_push_file_sample(&bob, 0x1000, "mayan.c");
				break;
			case 1:
				rz_bin_source_line_info_builder_push_file_sample(&bob, 0x1005, NULL);
				break;
			case 2:
				rz_bin_source_line_info_builder_push_file_sample(&bob, 0x1005, "mayan.c");
				break;
			case 3:
				rz_bin_source_line_info_builder_push_file_sample(&bob, 0x1010, NULL);
				break;
			case 4:
				rz_bin_source_line_info_builder_push_file_sample(&bob, 0x1010, "panoramas.c");
				break;
			case 5:
				rz_bin_source_line_info_builder_push_file_sample(&bob, 0x1020, "pyramid.c");
				break;
			case 6:
				rz_bin_source_line_info_builder_push_file_sample(&bob, 0x1020, "pyjamas.c");
				break;
			case 7:
				rz_bin_source_line_info_builder_push_file_sample(&bob, 0x1080, NULL);
				break;
			case 8:
				rz_bin_source_line_info_builder_push_file_sample(&bob, 0x1090, NULL);
				break;
			case 9:
				rz_bin_source_line_info_builder_push_file_sample(&bob, 0x2000, "pyramania.c");
				break;
			case 10:
				rz_bin_source_line_info_builder_push_line_sample(&bob, 0x1000, 42, 3);
				break;
			case 11:
				rz_bin_source_line_info_builder_push_line_sample(&bob, 0x1001, 42, 5);
				break;
			case 12:
				rz_bin_source_line_info_builder_push_line_sample(&bob, 0x1002, 1337, 1);
				break;
			case 13:
				rz_bin_source_line_info_builder_push_line_sample(&bob, 0x1002, 123, 2);
				break;
			case 14:
				rz_bin_source_line_info_builder_push_line_sample(&bob, 0x1005, 23, 0);
				break;
			case 15:
				rz_bin_source_line_info_builder_push_line_sample(&bob, 0x1005, 0, 0);
				break;
			case 16:
				rz_bin_source_line_info_builder_push_line_sample(&bob, 0x1100, 0, 0);
				break;
			case 17:
				rz_bin_source_line_info_builder_push_line_sample(&bob, 0x1103, 2, 2);
				break;
			default:
				break;
			}
		}

		RzBinSourceLineInfo *li = rz_bin_source_line_info_builder_build_and_fini(&bob);

		mu_assert_eq(li->files_count, 5, "files count");
		mu_assert_notnull(li->files, "files");
		mu_assert_eq(li->files[0].address, 0x1000, "file addr");
		mu_assert_streq(li->files[0].file, "mayan.c", "file str");
		mu_assert_eq(li->files[1].address, 0x1010, "file addr");
		mu_assert_streq(li->files[1].file, "panoramas.c", "file str");
		mu_assert_eq(li->files[2].address, 0x1020, "file addr");
		// whether this is "pyjamas.c" or "pyramid.c" is implementation-dependent
		// but it should be deterministic so we check for the concrete value.
		mu_assert_streq(li->files[2].file, "pyramid.c", "file str");
		mu_assert_eq(li->files[3].address, 0x1080, "file addr");
		mu_assert_null(li->files[3].file, "file str");
		mu_assert_eq(li->files[4].address, 0x2000, "file addr");
		mu_assert_streq(li->files[4].file, "pyramania.c", "file str");

		mu_assert_eq(li->lines_count, 6, "lines count");
		mu_assert_notnull(li->lines, "lines");
		mu_assert_eq(li->lines[0].address, 0x1000, "line addr");
		mu_assert_eq(li->lines[0].line, 42, "line line");
		mu_assert_eq(li->lines[0].column, 3, "line column");
		mu_assert_eq(li->lines[1].address, 0x1001, "line addr");
		mu_assert_eq(li->lines[1].line, 42, "line line");
		mu_assert_eq(li->lines[1].column, 5, "line column");
		// whether this is 123 or 1337 is implementation-dependent
		// but it should be deterministic so we check for the concrete value.
		mu_assert_eq(li->lines[2].address, 0x1002, "line addr");
		mu_assert_eq(li->lines[2].line, 1337, "line line");
		mu_assert_eq(li->lines[2].column, 1, "line column");
		mu_assert_eq(li->lines[3].address, 0x1005, "line addr");
		mu_assert_eq(li->lines[3].line, 23, "line line");
		mu_assert_eq(li->lines[3].column, 0, "line column");
		mu_assert_eq(li->lines[4].address, 0x1100, "line addr");
		mu_assert_eq(li->lines[4].line, 0, "line line");
		mu_assert_eq(li->lines[4].column, 0, "line column");
		mu_assert_eq(li->lines[5].address, 0x1103, "line addr");
		mu_assert_eq(li->lines[5].line, 2, "line line");
		mu_assert_eq(li->lines[5].column, 2, "line column");

		rz_bin_source_line_info_free(li);
	}
	mu_end;
}

bool test_source_line_info_builder_fuzz_lines() {
	for (size_t f = 0; f < FUZZ_COUNT; f++) {
		RzBinSourceLineInfoBuilder bob;
		rz_bin_source_line_info_builder_init(&bob);

		// generate a lot of random samples and check them against a
		// super slow but super simple equivalent algorithm
#define SAMPLES_COUNT 0x200
		RzBinSourceLine samples[SAMPLES_COUNT] = { 0 };
		HtUP *unique_addrs = ht_up_new0();
		size_t unique_addrs_count = 0;
		for (size_t i = 0; i < SAMPLES_COUNT; i++) {
			samples[i].address = rand() % 0x100;
			if (rand() % 10 > 2) {
				// non-closing entry
				samples[i].line = rand() % 42;
				samples[i].column = rand() % 42;
			}
			if (ht_up_insert(unique_addrs, samples[i].address, NULL)) {
				unique_addrs_count++;
			}
			rz_bin_source_line_info_builder_push_line_sample(&bob, samples[i].address, samples[i].line, samples[i].column);
		}
		RzBinSourceLineInfo *li = rz_bin_source_line_info_builder_build_and_fini(&bob);

		// resulting count should be exactly the number of unique addresses
		mu_assert_eq(li->lines_count, unique_addrs_count, "lines count");
		for (size_t i = 0; i < li->lines_count; i++) {
			RzBinSourceLine *actual = &li->lines[i];
			ut64 addr = actual->address;
			mu_assert_true(!!ht_up_find_kv(unique_addrs, addr, NULL), "addr");
			RzBinSourceLine *l = NULL;
			for (size_t j = 0; j < SAMPLES_COUNT; j++) {
				RzBinSourceLine *c = &samples[j];
				if (c->address != addr) {
					continue;
				}
				if (!l || c->line > l->line || (c->line == l->line && c->column > l->column)) {
					l = c;
				}
			}
			mu_assert_eq(actual->line, l->line, "line");
			mu_assert_eq(actual->column, l->column, "column");
		}

		ht_up_free(unique_addrs);
		rz_bin_source_line_info_free(li);
	}
#undef SAMPLES_COUNT
	mu_end;
}

bool test_source_line_info_query() {
	RzBinSourceFile files[] = {
		{ 0x1000, strdup("mayan.c") },
		{ 0x1010, strdup("panoramas.c") },
		{ 0x1020, strdup("pyramid.c") },
		{ 0x1080, NULL },
		{ 0x2000, strdup("pyramania.c") }
	};

	RzBinSourceLine lines[] = {
		{ 0x1000, 42, 3 },
		{ 0x1001, 42, 5 },
		{ 0x1002, 1337, 1 },
		{ 0x1005, 23, 0 },
		{ 0x1100, 0, 0 },
		{ 0x1103, 2, 2 }
	};

	RzBinSourceLineInfo *li = RZ_NEW0(RzBinSourceLineInfo);
	li->files = rz_mem_dup(files, sizeof(files));
	li->files_count = RZ_ARRAY_SIZE(files);
	li->lines = rz_mem_dup(lines, sizeof(lines));
	li->lines_count = RZ_ARRAY_SIZE(lines);

	const RzBinSourceFile *f = rz_bin_source_line_info_get_file_at(li, 0);
	mu_assert_null(f, "file");
	f = rz_bin_source_line_info_get_file_at(li, 0xfff);
	mu_assert_null(f, "file");
	f = rz_bin_source_line_info_get_file_at(li, 0x1000);
	mu_assert_notnull(f, "file");
	mu_assert_eq(f->address, 0x1000, "file addr");
	mu_assert_streq(f->file, "mayan.c", "file str");
	f = rz_bin_source_line_info_get_file_at(li, 0x100f);
	mu_assert_notnull(f, "file");
	mu_assert_eq(f->address, 0x1000, "file addr");
	mu_assert_streq(f->file, "mayan.c", "file str");
	f = rz_bin_source_line_info_get_file_at(li, 0x1010);
	mu_assert_notnull(f, "file");
	mu_assert_eq(f->address, 0x1010, "file addr");
	mu_assert_streq(f->file, "panoramas.c", "file str");
	f = rz_bin_source_line_info_get_file_at(li, 0x1030);
	mu_assert_notnull(f, "file");
	mu_assert_eq(f->address, 0x1020, "file addr");
	mu_assert_streq(f->file, "pyramid.c", "file str");
	f = rz_bin_source_line_info_get_file_at(li, 0x107f);
	mu_assert_notnull(f, "file");
	mu_assert_eq(f->address, 0x1020, "file addr");
	mu_assert_streq(f->file, "pyramid.c", "file str");
	f = rz_bin_source_line_info_get_file_at(li, 0x1080);
	mu_assert_null(f, "file");
	f = rz_bin_source_line_info_get_file_at(li, 0x1fff);
	mu_assert_null(f, "file");
	f = rz_bin_source_line_info_get_file_at(li, 0x2000);
	mu_assert_notnull(f, "file");
	mu_assert_eq(f->address, 0x2000, "file addr");
	mu_assert_streq(f->file, "pyramania.c", "file str");
	f = rz_bin_source_line_info_get_file_at(li, 0x500000);
	mu_assert_notnull(f, "file");
	mu_assert_eq(f->address, 0x2000, "file addr");
	mu_assert_streq(f->file, "pyramania.c", "file str");

	const RzBinSourceLine *l = rz_bin_source_line_info_get_line_at(li, 0);
	mu_assert_null(l, "line");
	l = rz_bin_source_line_info_get_line_at(li, 0xfff);
	mu_assert_null(l, "line");
	l = rz_bin_source_line_info_get_line_at(li, 0x1000);
	mu_assert_notnull(l, "line");
	mu_assert_eq(l->address, 0x1000, "line addr");
	mu_assert_eq(l->line, 42, "line line");
	mu_assert_eq(l->column, 3, "line column");
	l = rz_bin_source_line_info_get_line_at(li, 0x1001);
	mu_assert_notnull(l, "line");
	mu_assert_eq(l->address, 0x1001, "line addr");
	mu_assert_eq(l->line, 42, "line line");
	mu_assert_eq(l->column, 5, "line column");
	l = rz_bin_source_line_info_get_line_at(li, 0x1004);
	mu_assert_notnull(l, "line");
	mu_assert_eq(l->address, 0x1002, "line addr");
	mu_assert_eq(l->line, 1337, "line line");
	mu_assert_eq(l->column, 1, "line column");
	l = rz_bin_source_line_info_get_line_at(li, 0x1005);
	mu_assert_notnull(l, "line");
	mu_assert_eq(l->address, 0x1005, "line addr");
	mu_assert_eq(l->line, 23, "line line");
	mu_assert_eq(l->column, 0, "line column");
	l = rz_bin_source_line_info_get_line_at(li, 0x10ff);
	mu_assert_notnull(l, "line");
	mu_assert_eq(l->address, 0x1005, "line addr");
	mu_assert_eq(l->line, 23, "line line");
	mu_assert_eq(l->column, 0, "line column");
	l = rz_bin_source_line_info_get_line_at(li, 0x1100);
	mu_assert_null(l, "line");
	l = rz_bin_source_line_info_get_line_at(li, 0x1102);
	mu_assert_null(l, "line");
	l = rz_bin_source_line_info_get_line_at(li, 0x1103);
	mu_assert_notnull(l, "line");
	mu_assert_eq(l->address, 0x1103, "line addr");
	mu_assert_eq(l->line, 2, "line line");
	mu_assert_eq(l->column, 2, "line column");
	l = rz_bin_source_line_info_get_line_at(li, 0x424242);
	mu_assert_notnull(l, "line");
	mu_assert_eq(l->address, 0x1103, "line addr");
	mu_assert_eq(l->line, 2, "line line");
	mu_assert_eq(l->column, 2, "line column");

	rz_bin_source_line_info_free(li);
	mu_end;
}

bool all_tests() {
	srand(time(0));
	mu_run_test(test_source_line_info_builder_empty);
	mu_run_test(test_source_line_info_builder_fuzz_lines);
	mu_run_test(test_source_line_info_builder);
	mu_run_test(test_source_line_info_query);
	return tests_passed != tests_run;
}

mu_main(all_tests)
