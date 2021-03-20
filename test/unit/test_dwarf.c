// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#include <rz_bin.h>
#include <rz_core.h>
#include <rz_bin_dwarf.h>

#define check_abbrev_code(expected_code) \
	mu_assert_eq(da->decls[i].code, expected_code, "Wrong abbrev code");

#define check_abbrev_tag(expected_tag) \
	mu_assert_eq(da->decls[i].tag, expected_tag, "Incorrect abbreviation tag")

#define check_abbrev_count(expected_count) \
	mu_assert_eq(da->decls[i].count, expected_count, "Incorrect abbreviation count")

#define check_abbrev_children(expected_children) \
	mu_assert_eq(da->decls[i].has_children, expected_children, "Incorrect children flag")

#define check_abbrev_attr_name(expected_name) \
	mu_assert_eq(da->decls[i].defs[j].attr_name, expected_name, "Incorrect children flag");

#define check_abbrev_attr_form(expected_form) \
	mu_assert_eq(da->decls[i].defs[j].attr_form, expected_form, "Incorrect children flag");

static bool check_source_files_eq(const RzBinSourceLineInfo *actual,
	size_t files_count_expect, const RzBinSourceFile *files_expect) {
	mu_assert_eq(actual->files_count, files_count_expect, "files count");
	if (files_expect) {
		mu_assert_notnull(actual->files, "files");
		for (size_t i = 0; i < files_count_expect; i++) {
			mu_assert_eq(actual->files[i].address, files_expect[i].address, "file addr");
			mu_assert_streq(actual->files[i].file, files_expect[i].file, "file str");
		}
	} else {
		mu_assert_null(actual->files, "files");
	}
	return true;
}

static void print_source_files(size_t files_count, const RzBinSourceFile *files) {
	printf("{\n");
	for (size_t i = 0; i < files_count; i++) {
		printf("\t{ 0x%" PFMT64x ", %s%s%s }%s\n",
			files[i].address,
			files[i].file ? "\"" : "",
			files[i].file ? files[i].file : "NULL",
			files[i].file ? "\"" : "",
			i + 1 < files_count ? "," : "");
	}
	printf("};\n");
}

#define assert_source_files_eq(actual, count_expect, files_expect) \
	do { \
		if (!check_source_files_eq(actual, count_expect, files_expect)) { \
			printf("---- EXPECTED:\n"); \
			print_source_files(count_expect, files_expect); \
			printf("---- GOT:\n"); \
			print_source_files(actual->files_count, actual->files); \
			return false; \
		} \
	} while (0);

static bool check_source_lines_eq(const RzBinSourceLineInfo *actual,
	size_t lines_count_expect, const RzBinSourceLine *lines_expect) {
	mu_assert_eq(actual->lines_count, lines_count_expect, "lines count");
	if (lines_expect) {
		mu_assert_notnull(actual->lines, "lines");
		for (size_t i = 0; i < lines_count_expect; i++) {
			mu_assert_eq(actual->lines[i].address, lines_expect[i].address, "line addr");
			mu_assert_eq(actual->lines[i].line, lines_expect[i].line, "line line");
			mu_assert_eq(actual->lines[i].column, lines_expect[i].column, "line column");
		}
	} else {
		mu_assert_null(actual->lines, "lines");
	}
	return true;
}

static void print_source_lines(size_t lines_count, const RzBinSourceLine *lines) {
	printf("{\n");
	for (size_t i = 0; i < lines_count; i++) {
		printf("\t{ 0x%" PFMT64x ", %" PFMT32u ", %" PFMT32u " }%s\n",
			lines[i].address, lines[i].line, lines[i].column, i + 1 < lines_count ? "," : "");
	}
	printf("};\n");
}

#define assert_source_lines_eq(actual, count_expect, lines_expect) \
	do { \
		if (!check_source_lines_eq(actual, count_expect, lines_expect)) { \
			printf("---- EXPECTED:\n"); \
			print_source_lines(count_expect, lines_expect); \
			printf("---- GOT:\n"); \
			print_source_lines(actual->lines_count, actual->lines); \
			return false; \
		} \
	} while (0);

/**
 * @brief Tests correct parsing of abbreviations and line information of DWARF3 C binary
 */
bool test_dwarf3_c_basic(void) { // this should work for dwarf2 aswell
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf3_c.elf", &opt);
	mu_assert("couldn't open file", res);

	RzBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_parse_abbrev(bin->cur);
	mu_assert_eq(da->count, 7, "Incorrect number of abbreviation");

	// order matters
	// I nest scopes to make it more readable, (hopefully)
	int i = 0;
	check_abbrev_tag(DW_TAG_compile_unit);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
		{
			int j = 0;
			check_abbrev_attr_name(DW_AT_producer);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_language);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_name);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_comp_dir);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_low_pc);
			check_abbrev_attr_form(DW_FORM_addr);
			j++;
			check_abbrev_attr_name(DW_AT_high_pc);
			check_abbrev_attr_form(DW_FORM_addr);
			j++;
			check_abbrev_attr_name(DW_AT_stmt_list);
			check_abbrev_attr_form(DW_FORM_data4);
		}
	}
	i++;
	check_abbrev_tag(DW_TAG_variable);
	{
		check_abbrev_count(8);
		check_abbrev_children(false);
	}
	i++;
	check_abbrev_tag(DW_TAG_base_type);
	{
		check_abbrev_count(4);
		check_abbrev_children(false);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_count(12);
		check_abbrev_children(true);
	}
	i++;
	check_abbrev_tag(DW_TAG_variable);
	{
		check_abbrev_count(7);
		check_abbrev_children(false);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_count(10);
		check_abbrev_children(true);
	}
	i++;
	check_abbrev_tag(DW_TAG_variable);
	{
		check_abbrev_count(6);
		check_abbrev_children(false);
	}
	i++;

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 1, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceFile test_files[] = {
		{ 0x1129, ".//main.c" },
		{ 0x1156, NULL }
	};
	const RzBinSourceLine test_lines[] = {
		{ 0x1129, 3, 1 },
		{ 0x1131, 6, 1 },
		{ 0x1134, 7, 12 },
		{ 0x1140, 8, 2 },
		{ 0x114a, 9, 6 },
		{ 0x1151, 10, 9 },
		{ 0x1154, 11, 1 },
		{ 0x1156, 0, 0 }
	};
	assert_source_files_eq(li->lines, RZ_ARRAY_SIZE(test_files), test_files);
	assert_source_lines_eq(li->lines, RZ_ARRAY_SIZE(test_lines), test_lines);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_dwarf_debug_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

/**
 * @brief Tests correct parsing of abbreviations and line information of DWARF3 C++ binary
 * 
 * 
 * 
 * 
 */
bool test_dwarf3_cpp_basic(void) { // this should work for dwarf2 aswell
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf3_cpp.elf", &opt);
	mu_assert("couldn't open file", res);

	// this is probably ugly, but I didn't know how to
	// tell core  what bin to open so I did it myself

	RzBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_parse_abbrev(bin->cur);
	mu_assert("Incorrect number of abbreviation", da->count == 32);

	// order matters
	// I nest scopes to make it more readable, (hopefully)
	int i = 0;
	check_abbrev_tag(DW_TAG_compile_unit);
	{
		check_abbrev_children(true);
		check_abbrev_count(9);
		{
			/**
			 *  Everything commented out is something that is missing from being printed by `id` Radare
			 */
			int j = 0;
			check_abbrev_attr_name(DW_AT_producer);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_language);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_name);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_comp_dir);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_ranges);
			check_abbrev_attr_form(DW_FORM_data4);
			j++;
			check_abbrev_attr_name(DW_AT_low_pc);
			check_abbrev_attr_form(DW_FORM_addr);
			j++;
			check_abbrev_attr_name(DW_AT_entry_pc);
			check_abbrev_attr_form(DW_FORM_addr);
			j++;
			check_abbrev_attr_name(DW_AT_stmt_list);
			check_abbrev_attr_form(DW_FORM_data4);

			// check_abbrev_attr_name (DW_AT value: 0);
			// check_abbrev_attr_form (DW_AT value: 0);
		}
	}
	i++;
	check_abbrev_tag(DW_TAG_structure_type);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
		{
			/**
			 *  Everything commented out is something that is missing from being printed by `id` Radare
			 */
			int j = 0;
			check_abbrev_attr_name(DW_AT_name);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_byte_size);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_decl_file);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_decl_line);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_decl_column);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_containing_type);
			check_abbrev_attr_form(DW_FORM_ref4);
			j++;
			check_abbrev_attr_name(DW_AT_sibling);
			check_abbrev_attr_form(DW_FORM_ref4);

			// check_abbrev_attr_name (DW_AT value: 0);
			// check_abbrev_attr_form (DW_AT value: 0);
		}
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
	}
	i++;
	check_abbrev_tag(DW_TAG_formal_parameter);
	{
		check_abbrev_children(false);
		check_abbrev_count(3);
	}
	i++;
	check_abbrev_tag(DW_TAG_formal_parameter);
	{
		check_abbrev_children(false);
		check_abbrev_count(2);
	}
	i++;
	check_abbrev_tag(DW_TAG_member);
	{
		check_abbrev_children(false);
		check_abbrev_count(5);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(10);
	}
	i++;

	// 8
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(12);
		{
			int j = 0;
			check_abbrev_attr_name(DW_AT_external);
			check_abbrev_attr_form(DW_FORM_flag);
			j++;
			check_abbrev_attr_name(DW_AT_name);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_decl_file);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_decl_line);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_decl_column);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			// check_abbrev_attr_name (DW_AT_MIPS_linkage_name);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_virtuality);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_containing_type);
			check_abbrev_attr_form(DW_FORM_ref4);
			j++;
			check_abbrev_attr_name(DW_AT_declaration);
			check_abbrev_attr_form(DW_FORM_flag);
			j++;
			check_abbrev_attr_name(DW_AT_object_pointer);
			check_abbrev_attr_form(DW_FORM_ref4);
			j++;
			check_abbrev_attr_name(DW_AT_sibling);
			check_abbrev_attr_form(DW_FORM_ref4);
		}
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(13);
	}
	i++;
	check_abbrev_tag(DW_TAG_const_type);
	{
		check_abbrev_children(false);
		check_abbrev_count(2);
	}
	i++;
	check_abbrev_tag(DW_TAG_pointer_type);
	{
		check_abbrev_children(false);
		check_abbrev_count(3);
	}
	i++;
	check_abbrev_tag(DW_TAG_reference_type);
	{
		check_abbrev_children(false);
		check_abbrev_count(3);
	}
	i++;
	check_abbrev_tag(DW_TAG_subroutine_type);
	{
		check_abbrev_children(true);
		check_abbrev_count(3);
	}
	i++;
	check_abbrev_tag(DW_TAG_unspecified_parameters);
	{
		check_abbrev_children(false);
		check_abbrev_count(1);
	}
	i++;
	check_abbrev_tag(DW_TAG_base_type);
	{
		check_abbrev_children(false);
		check_abbrev_count(4);
	}
	i++;
	check_abbrev_tag(DW_TAG_pointer_type);
	{
		check_abbrev_children(false);
		check_abbrev_count(4);
	}
	i++;
	check_abbrev_tag(DW_TAG_structure_type);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
	}
	i++;
	check_abbrev_tag(DW_TAG_inheritance);
	{
		check_abbrev_children(false);
		check_abbrev_count(3);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(10);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(13);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(12);
	}
	i++;
	check_abbrev_tag(DW_TAG_variable);
	{
		check_abbrev_children(false);
		check_abbrev_count(7);
	}
	i++;
	check_abbrev_tag(DW_TAG_variable);
	{
		check_abbrev_children(false);
		check_abbrev_count(7);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
	}
	i++;
	check_abbrev_tag(DW_TAG_formal_parameter);
	{
		check_abbrev_children(false);
		check_abbrev_count(5);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(5);
	}
	i++;
	check_abbrev_tag(DW_TAG_formal_parameter);
	{
		check_abbrev_children(false);
		check_abbrev_count(4);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(9);
	}
	i++;
	check_abbrev_tag(DW_TAG_formal_parameter);
	{
		check_abbrev_children(false);
		check_abbrev_count(3);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(9);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
	}

	// rz_bin_dwarf_parse_info (da, core->bin, mode); Information not stored anywhere, not testable now?

	// rz_bin_dwarf_parse_aranges (core->bin, MODE); Information not stored anywhere, not testable now?

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 1, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceFile test_files[] = {
		{ 0x1169, ".//main.cpp" },
		{ 0x11ed, NULL },
		{ 0x11ee, ".//main.cpp" },
		{ 0x120b, NULL },
		{ 0x120c, ".//main.cpp" },
		{ 0x1229, NULL },
		{ 0x122a, ".//main.cpp" },
		{ 0x1259, NULL },
		{ 0x125a, ".//main.cpp" },
		{ 0x126d, NULL },
		{ 0x126e, ".//main.cpp" },
		{ 0x129b, NULL },
		{ 0x129c, ".//main.cpp" },
		{ 0x12c9, NULL },
		{ 0x12ca, ".//main.cpp" },
		{ 0x12f9, NULL },
		{ 0x12fa, ".//main.cpp" },
		{ 0x130d, NULL },
		{ 0x130e, ".//main.cpp" },
		{ 0x132b, NULL },
		{ 0x132c, ".//main.cpp" },
		{ 0x1349, NULL },
		{ 0x134a, ".//main.cpp" },
		{ 0x1379, NULL },
		{ 0x137a, ".//main.cpp" },
		{ 0x138d, NULL }
	};
	const RzBinSourceLine test_lines[] = {
		{ 0x1169, 19, 12 },
		{ 0x1176, 22, 16 },
		{ 0x118b, 22, 5 },
		{ 0x118f, 23, 15 },
		{ 0x11a4, 23, 5 },
		{ 0x11a8, 24, 7 },
		{ 0x11af, 25, 20 },
		{ 0x11bd, 25, 19 },
		{ 0x11c6, 25, 10 },
		{ 0x11c9, 26, 21 },
		{ 0x11d7, 26, 20 },
		{ 0x11e0, 26, 10 },
		{ 0x11e3, 27, 10 },
		{ 0x11e6, 28, 1 },
		{ 0x11ed, 0, 0 },
		{ 0x11ee, 2, 3 },
		{ 0x11fa, 2, 12 },
		{ 0x1208, 2, 15 },
		{ 0x120b, 0, 0 },
		{ 0x120c, 3, 11 },
		{ 0x1218, 3, 21 },
		{ 0x1226, 3, 22 },
		{ 0x1229, 0, 0 },
		{ 0x122a, 3, 11 },
		{ 0x123a, 3, 22 },
		{ 0x1259, 0, 0 },
		{ 0x125a, 4, 15 },
		{ 0x1266, 4, 31 },
		{ 0x126b, 4, 34 },
		{ 0x126d, 0, 0 },
		{ 0x126e, 8, 3 },
		{ 0x127e, 8, 9 },
		{ 0x1298, 8, 12 },
		{ 0x129b, 0, 0 },
		{ 0x129c, 9, 11 },
		{ 0x12ac, 9, 18 },
		{ 0x12c6, 9, 19 },
		{ 0x12c9, 0, 0 },
		{ 0x12ca, 9, 11 },
		{ 0x12da, 9, 19 },
		{ 0x12f9, 0, 0 },
		{ 0x12fa, 10, 15 },
		{ 0x1306, 10, 31 },
		{ 0x130b, 10, 34 },
		{ 0x130d, 0, 0 },
		{ 0x130e, 14, 3 },
		{ 0x131a, 14, 10 },
		{ 0x1328, 14, 13 },
		{ 0x132b, 0, 0 },
		{ 0x132c, 15, 11 },
		{ 0x1338, 15, 19 },
		{ 0x1346, 15, 20 },
		{ 0x1349, 0, 0 },
		{ 0x134a, 15, 11 },
		{ 0x135a, 15, 20 },
		{ 0x1379, 0, 0 },
		{ 0x137a, 16, 15 },
		{ 0x1386, 16, 30 },
		{ 0x138b, 16, 33 },
		{ 0x138d, 0, 0 }
	};
	assert_source_files_eq(li->lines, RZ_ARRAY_SIZE(test_files), test_files);
	assert_source_lines_eq(li->lines, RZ_ARRAY_SIZE(test_lines), test_lines);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_dwarf_debug_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf3_cpp_many_comp_units(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf3_many_comp_units.elf", &opt);
	mu_assert("couldn't open file", res);

	RzBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_parse_abbrev(bin->cur);
	mu_assert_eq(da->count, 58, "Incorrect number of abbreviation");
	int i = 18;

	check_abbrev_tag(DW_TAG_formal_parameter);
	check_abbrev_count(5);
	check_abbrev_children(false);
	check_abbrev_code(19);
	i = 41;
	check_abbrev_tag(DW_TAG_inheritance);
	check_abbrev_count(3);
	check_abbrev_children(false);
	check_abbrev_code(18);

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 2, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceFile test_files[] = {
		{ 0x118a, ".//mammal.cpp" },
		{ 0x123b, ".//main.cpp" },
		{ 0x12c6, ".//mammal.h" },
		{ 0x12e3, NULL },
		{ 0x12e4, ".//main.cpp" },
		{ 0x1311, NULL },
		{ 0x1312, ".//main.cpp" },
		{ 0x133f, NULL },
		{ 0x1340, ".//main.cpp" },
		{ 0x136f, NULL },
		{ 0x1370, ".//main.cpp" },
		{ 0x1383, NULL },
		{ 0x1384, ".//main.cpp" },
		{ 0x13a1, NULL },
		{ 0x13a2, ".//main.cpp" },
		{ 0x13bf, NULL },
		{ 0x13c0, ".//main.cpp" },
		{ 0x13ef, NULL },
		{ 0x13f0, ".//main.cpp" },
		{ 0x1403, NULL }
	};
	const RzBinSourceLine test_lines[] = {
		{ 0x118a, 3, 3 },
		{ 0x1196, 3, 19 },
		{ 0x11a4, 3, 22 },
		{ 0x11a8, 3, 3 },
		{ 0x11b8, 3, 22 },
		{ 0x11d8, 4, 22 },
		{ 0x11e4, 4, 31 },
		{ 0x11e9, 4, 34 },
		{ 0x11eb, 10, 12 },
		{ 0x11f7, 10, 12 },
		{ 0x1206, 12, 23 },
		{ 0x1212, 13, 1 },
		{ 0x1228, 7, 0 },
		{ 0x1234, 7, 26 },
		{ 0x1239, 7, 28 },
		{ 0x123b, 15, 0 },
		{ 0x1248, 18, 16 },
		{ 0x125d, 18, 5 },
		{ 0x1261, 19, 15 },
		{ 0x1276, 19, 5 },
		{ 0x127a, 20, 7 },
		{ 0x1281, 21, 20 },
		{ 0x128f, 21, 19 },
		{ 0x1298, 21, 10 },
		{ 0x129b, 22, 21 },
		{ 0x12a9, 22, 20 },
		{ 0x12b2, 22, 10 },
		{ 0x12b5, 23, 23 },
		{ 0x12ba, 23, 24 },
		{ 0x12bf, 24, 1 },
		{ 0x12c6, 2, 3 },
		{ 0x12d2, 2, 12 },
		{ 0x12e0, 2, 15 },
		{ 0x12e3, 0, 0 },
		{ 0x12e4, 4, 3 },
		{ 0x12f4, 4, 9 },
		{ 0x130e, 4, 12 },
		{ 0x1311, 0, 0 },
		{ 0x1312, 5, 11 },
		{ 0x1322, 5, 18 },
		{ 0x133c, 5, 19 },
		{ 0x133f, 0, 0 },
		{ 0x1340, 5, 11 },
		{ 0x1350, 5, 19 },
		{ 0x136f, 0, 0 },
		{ 0x1370, 6, 15 },
		{ 0x137c, 6, 31 },
		{ 0x1381, 6, 34 },
		{ 0x1383, 0, 0 },
		{ 0x1384, 10, 3 },
		{ 0x1390, 10, 10 },
		{ 0x139e, 10, 13 },
		{ 0x13a1, 0, 0 },
		{ 0x13a2, 11, 11 },
		{ 0x13ae, 11, 19 },
		{ 0x13bc, 11, 20 },
		{ 0x13bf, 0, 0 },
		{ 0x13c0, 11, 11 },
		{ 0x13d0, 11, 20 },
		{ 0x13ef, 0, 0 },
		{ 0x13f0, 12, 15 },
		{ 0x13fc, 12, 30 },
		{ 0x1401, 12, 33 },
		{ 0x1403, 0, 0 }
	};
	assert_source_files_eq(li->lines, RZ_ARRAY_SIZE(test_files), test_files);
	assert_source_lines_eq(li->lines, RZ_ARRAY_SIZE(test_lines), test_lines);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_dwarf_debug_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf_cpp_empty_line_info(void) { // this should work for dwarf2 aswell
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/pe/hello_world_not_stripped.exe", &opt);
	mu_assert("couldn't open file", res);

	RzBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_parse_abbrev(bin->cur);
	// not ignoring null entries -> 755 abbrevs
	mu_assert_eq(da->count, 731, "Incorrect number of abbreviation");

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 16, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceFile test_files[] = {
		{ 0x401000, "../crt/crtexe.c" },
		{ 0x4011d2, "/usr/local/Cellar/mingw-w64/5.0.4_1/toolchain-i686/i686-w64-mingw32/include/winnt.h" },
		{ 0x4011da, "../crt/crtexe.c" },
		{ 0x4011f9, "/usr/local/Cellar/mingw-w64/5.0.4_1/toolchain-i686/i686-w64-mingw32/include/psdk_inc/intrin-impl.h" },
		{ 0x401203, "../crt/crtexe.c" },
		{ 0x401453, "/usr/local/Cellar/mingw-w64/5.0.4_1/toolchain-i686/i686-w64-mingw32/include/psdk_inc/intrin-impl.h" },
		{ 0x401460, "../crt/crtexe.c" },
		{ 0x4014fa, NULL },
		{ 0x401560, "../crt/atonexit.c" },
		{ 0x40163d, NULL },
		{ 0x401640, "../crt/gccmain.c" },
		{ 0x4016ec, NULL },
		{ 0x4016f0, "../crt/charmax.c" },
		{ 0x4016f6, NULL },
		{ 0x401700, "../crt/dllargv.c" },
		{ 0x401703, NULL },
		{ 0x401710, "../crt/gs_support.c" },
		{ 0x401847, NULL },
		{ 0x401850, "../crt/tlssup.c" },
		{ 0x401933, NULL },
		{ 0x401940, "../crt/merr.c" },
		{ 0x4019fb, NULL },
		{ 0x401a00, "../crt/CRT_fp10.c" },
		{ 0x401a03, NULL },
		{ 0x401a20, "../crt/mingw_helpers.c" },
		{ 0x401a25, NULL },
		{ 0x401a30, "../crt/pseudo-reloc.c" },
		{ 0x401e3b, NULL },
		{ 0x401e40, "../crt/crt_handler.c" },
		{ 0x401fe6, NULL },
		{ 0x401ff0, "../crt/tlsthrd.c" },
		{ 0x402282, NULL },
		{ 0x402290, "../crt/pesect.c" },
		{ 0x402617, NULL },
		{ 0x402620, "../../../libgcc/config/i386/cygwin.S" },
		{ 0x40264a, NULL },
		{ 0x402700, "../misc/invalid_parameter_handler.c" },
		{ 0x402710, "/usr/local/Cellar/mingw-w64/5.0.4_1/toolchain-i686/i686-w64-mingw32/include/psdk_inc/intrin-impl.h" },
		{ 0x40271a, "../misc/invalid_parameter_handler.c" },
		{ 0x40271b, NULL }
	};
	assert_source_files_eq(li->lines, RZ_ARRAY_SIZE(test_files), test_files);

	const ut64 test_addresses[] = {
		0x00401000,
		0x00401010,
		0x00401013,
		0x00401015,
		0x0040101e,
		0x00401028,
		0x00401032,
		0x0040103c,
		0x00401046
	};
	mu_assert_eq(li->lines->lines_count, 0x303, "lines count");
	for (size_t i = 0; i < RZ_ARRAY_SIZE(test_addresses); i++) {
		mu_assert_eq(li->lines->lines[i].address, test_addresses[i], "line addr");
	}

	rz_bin_dwarf_line_info_free(li);

	rz_bin_dwarf_debug_abbrev_free(da);
	rz_io_free(io);
	rz_bin_free(bin);
	mu_end;
}

bool test_dwarf2_cpp_many_comp_units(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf2_many_comp_units.elf", &opt);
	mu_assert("couldn't open file", res);

	RzBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_parse_abbrev(bin->cur);
	mu_assert_eq(da->count, 58, "Incorrect number of abbreviation");

	int i = 18;

	check_abbrev_tag(DW_TAG_formal_parameter);
	check_abbrev_count(5);
	check_abbrev_children(false);
	check_abbrev_code(19);
	i = 41;
	check_abbrev_tag(DW_TAG_inheritance);
	check_abbrev_count(4);
	check_abbrev_children(false);
	check_abbrev_code(18);

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 2, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceFile test_files[] = {
		{ 0x118a, ".//mammal.cpp" },
		{ 0x123b, ".//main.cpp" },
		{ 0x12c6, ".//mammal.h" },
		{ 0x12e3, NULL },
		{ 0x12e4, ".//main.cpp" },
		{ 0x1311, NULL },
		{ 0x1312, ".//main.cpp" },
		{ 0x133f, NULL },
		{ 0x1340, ".//main.cpp" },
		{ 0x136f, NULL },
		{ 0x1370, ".//main.cpp" },
		{ 0x1383, NULL },
		{ 0x1384, ".//main.cpp" },
		{ 0x13a1, NULL },
		{ 0x13a2, ".//main.cpp" },
		{ 0x13bf, NULL },
		{ 0x13c0, ".//main.cpp" },
		{ 0x13ef, NULL },
		{ 0x13f0, ".//main.cpp" },
		{ 0x1403, NULL }
	};
	const RzBinSourceLine test_lines[] = {
		{ 0x118a, 3, 3 },
		{ 0x1196, 3, 19 },
		{ 0x11a4, 3, 22 },
		{ 0x11a8, 3, 3 },
		{ 0x11b8, 3, 22 },
		{ 0x11d8, 4, 22 },
		{ 0x11e4, 4, 31 },
		{ 0x11e9, 4, 34 },
		{ 0x11eb, 10, 12 },
		{ 0x11f7, 10, 12 },
		{ 0x1206, 12, 23 },
		{ 0x1212, 13, 1 },
		{ 0x1228, 7, 6 },
		{ 0x1234, 7, 26 },
		{ 0x1239, 7, 28 },
		{ 0x123b, 15, 0 },
		{ 0x1248, 18, 16 },
		{ 0x125d, 18, 5 },
		{ 0x1261, 19, 15 },
		{ 0x1276, 19, 5 },
		{ 0x127a, 20, 7 },
		{ 0x1281, 21, 20 },
		{ 0x128f, 21, 19 },
		{ 0x1298, 21, 10 },
		{ 0x129b, 22, 21 },
		{ 0x12a9, 22, 20 },
		{ 0x12b2, 22, 10 },
		{ 0x12b5, 23, 23 },
		{ 0x12ba, 23, 24 },
		{ 0x12bf, 24, 1 },
		{ 0x12c6, 2, 0 },
		{ 0x12d2, 2, 12 },
		{ 0x12e0, 2, 15 },
		{ 0x12e3, 0, 0 },
		{ 0x12e4, 4, 3 },
		{ 0x12f4, 4, 9 },
		{ 0x130e, 4, 12 },
		{ 0x1311, 0, 0 },
		{ 0x1312, 5, 11 },
		{ 0x1322, 5, 18 },
		{ 0x133c, 5, 19 },
		{ 0x133f, 0, 0 },
		{ 0x1340, 5, 11 },
		{ 0x1350, 5, 19 },
		{ 0x136f, 0, 0 },
		{ 0x1370, 6, 15 },
		{ 0x137c, 6, 31 },
		{ 0x1381, 6, 34 },
		{ 0x1383, 0, 0 },
		{ 0x1384, 10, 3 },
		{ 0x1390, 10, 10 },
		{ 0x139e, 10, 13 },
		{ 0x13a1, 0, 0 },
		{ 0x13a2, 11, 11 },
		{ 0x13ae, 11, 19 },
		{ 0x13bc, 11, 20 },
		{ 0x13bf, 0, 0 },
		{ 0x13c0, 11, 11 },
		{ 0x13d0, 11, 20 },
		{ 0x13ef, 0, 0 },
		{ 0x13f0, 12, 15 },
		{ 0x13fc, 12, 30 },
		{ 0x1401, 12, 33 },
		{ 0x1403, 0, 0 }
	};
	assert_source_files_eq(li->lines, RZ_ARRAY_SIZE(test_files), test_files);
	assert_source_lines_eq(li->lines, RZ_ARRAY_SIZE(test_lines), test_lines);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_dwarf_debug_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf4_cpp_many_comp_units(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf4_many_comp_units.elf", &opt);
	mu_assert("couldn't open file", res);

	// TODO add abbrev checks

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 2, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceFile test_files[] = {
		{ 0x401160, "../main.cpp" },
		{ 0x401194, NULL },
		{ 0x401240, "../main.cpp" },
		{ 0x401261, NULL },
		{ 0x401270, "../main.cpp" },
		{ 0x4012ac, NULL },
		{ 0x4012b0, "../main.cpp" },
		{ 0x4012ba, NULL },
		{ 0x4012c0, "../main.cpp" },
		{ 0x4012ee, NULL },
		{ 0x4012f0, "../main.cpp" },
		{ 0x4012ff, NULL },
		{ 0x401300, "../mammal.h" },
		{ 0x401321, NULL },
		{ 0x401330, "../main.cpp" },
		{ 0x40134e, NULL },
		{ 0x401350, "../main.cpp" },
		{ 0x40137e, NULL },
		{ 0x401380, "../main.cpp" },
		{ 0x40138f, NULL },
		{ 0x401390, "../mammal.cpp" },
		{ 0x4013f7, NULL },
		{ 0x401400, "../mammal.cpp" },
		{ 0x40140f, NULL }
	};
	const RzBinSourceLine test_lines[] = {
		{ 0x401160, 15, 0 },
		{ 0x401174, 18, 7 },
		{ 0x40117f, 18, 11 },
		{ 0x401194, 0, 11 },
		{ 0x401198, 18, 5 },
		{ 0x4011a1, 19, 7 },
		{ 0x4011ac, 19, 11 },
		{ 0x4011c1, 0, 11 },
		{ 0x4011c5, 19, 5 },
		{ 0x4011c9, 20, 7 },
		{ 0x4011d0, 21, 13 },
		{ 0x4011d4, 21, 16 },
		{ 0x4011dd, 21, 10 },
		{ 0x4011e3, 22, 13 },
		{ 0x4011e7, 22, 16 },
		{ 0x4011f0, 22, 10 },
		{ 0x4011f6, 23, 10 },
		{ 0x4011fc, 23, 19 },
		{ 0x401204, 23, 17 },
		{ 0x401206, 23, 3 },
		{ 0x40120e, 24, 1 },
		{ 0x401219, 18, 7 },
		{ 0x401223, 24, 1 },
		{ 0x40122e, 19, 7 },
		{ 0x401233, 18, 7 },
		{ 0x40123c, 0, 0 },
		{ 0x401240, 10, 0 },
		{ 0x40125c, 10, 10 },
		{ 0x40125f, 10, 13 },
		{ 0x401261, 0, 0 },
		{ 0x401270, 4, 0 },
		{ 0x401280, 4, 9 },
		{ 0x401283, 4, 3 },
		{ 0x4012a3, 4, 9 },
		{ 0x4012a6, 4, 12 },
		{ 0x4012ac, 0, 0 },
		{ 0x4012b0, 11, 0 },
		{ 0x4012b8, 11, 20 },
		{ 0x4012ba, 0, 0 },
		{ 0x4012c0, 11, 0 },
		{ 0x4012d0, 11, 19 },
		{ 0x4012e8, 11, 20 },
		{ 0x4012ee, 0, 0 },
		{ 0x4012f0, 12, 0 },
		{ 0x4012f8, 12, 23 },
		{ 0x4012ff, 0, 0 },
		{ 0x401300, 2, 0 },
		{ 0x40131c, 2, 12 },
		{ 0x40131f, 2, 15 },
		{ 0x401321, 0, 0 },
		{ 0x401330, 5, 0 },
		{ 0x401340, 5, 19 },
		{ 0x401348, 5, 19 },
		{ 0x40134e, 0, 0 },
		{ 0x401350, 5, 0 },
		{ 0x401360, 5, 18 },
		{ 0x401378, 5, 19 },
		{ 0x40137e, 0, 0 },
		{ 0x401380, 6, 0 },
		{ 0x401388, 6, 24 },
		{ 0x40138f, 0, 0 },
		{ 0x401390, 3, 0 },
		{ 0x401398, 3, 22 },
		{ 0x4013a0, 3, 0 },
		{ 0x4013b0, 3, 21 },
		{ 0x4013c8, 3, 22 },
		{ 0x4013d0, 4, 0 },
		{ 0x4013d8, 4, 24 },
		{ 0x4013e0, 10, 0 },
		{ 0x4013e8, 12, 14 },
		{ 0x4013f1, 12, 2 },
		{ 0x4013f7, 0, 0 },
		{ 0x401400, 7, 0 },
		{ 0x401408, 7, 19 },
		{ 0x40140f, 0, 0 }
	};
	assert_source_files_eq(li->lines, RZ_ARRAY_SIZE(test_files), test_files);
	assert_source_lines_eq(li->lines, RZ_ARRAY_SIZE(test_lines), test_lines);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf4_multidir_comp_units(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf4_multidir_comp_units", &opt);
	mu_assert("couldn't open file", res);

	RzBinDwarfDebugAbbrev *da = rz_bin_dwarf_parse_abbrev(bin->cur);
	mu_assert_notnull(da, "abbrevs");
	mu_assert_eq(da->count, 8, "abbrevs count");

	RzBinDwarfDebugInfo *info = rz_bin_dwarf_parse_info(bin->cur, da);
	mu_assert_notnull(info, "info");

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 2, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceFile test_files[] = {
		{ 0x1139, ".//main.c" },
		{ 0x1188, ".//subfile.c" },
		{ 0x11a5, NULL }
	};
	const RzBinSourceLine test_lines[] = {
		{ 0x1139, 6, 12 },
		{ 0x113d, 7, 2 },
		{ 0x115f, 8, 2 },
		{ 0x1181, 9, 9 },
		{ 0x1186, 10, 1 },
		{ 0x1188, 2, 31 },
		{ 0x1192, 3, 11 },
		{ 0x1198, 3, 20 },
		{ 0x11a1, 3, 16 },
		{ 0x11a3, 4, 1 },
		{ 0x11a5, 0, 0 }
	};
	assert_source_files_eq(li->lines, RZ_ARRAY_SIZE(test_files), test_files);
	assert_source_lines_eq(li->lines, RZ_ARRAY_SIZE(test_lines), test_lines);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_dwarf_debug_info_free(info);
	rz_bin_dwarf_debug_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_big_endian_dwarf2(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/ppc64_sudoku_dwarf", &opt);
	mu_assert("couldn't open file", res);

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 1, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceFile test_files[] = {
		{ 0x10000ec4, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f44, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10000f60, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000fcc, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10000fe4, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001014, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10001030, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001048, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10001060, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000108c, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100010a8, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100010c4, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100010e0, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100010fc, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001108, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/basic_ios.h" },
		{ 0x1000111c, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x1000112c, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10001144, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001180, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100011ac, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/basic_ios.h" },
		{ 0x100011b4, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x100011e4, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100011f0, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/basic_ios.h" },
		{ 0x10001204, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001214, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10001230, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/basic_ios.h" },
		{ 0x10001238, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001268, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001a0c, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001ac8, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b68, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001b6c, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b78, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001b7c, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001bf8, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/iostream" },
		{ 0x10001c28, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001c48, NULL }
	};
	const RzBinSourceLine test_lines[] = {
		{ 0x10000ec4, 30, 1 },
		{ 0x10000f18, 31, 5 },
		{ 0x10000f28, 32, 5 },
		{ 0x10000f2c, 31, 11 },
		{ 0x10000f30, 32, 13 },
		{ 0x10000f34, 34, 17 },
		{ 0x10000f38, 53, 22 },
		{ 0x10000f44, 570, 18 },
		{ 0x10000f5c, 572, 14 },
		{ 0x10000f60, 570, 18 },
		{ 0x10000f78, 53, 13 },
		{ 0x10000f80, 53, 22 },
		{ 0x10000f90, 53, 13 },
		{ 0x10000f98, 54, 13 },
		{ 0x10000fa0, 55, 13 },
		{ 0x10000fa4, 36, 13 },
		{ 0x10000fb4, 38, 17 },
		{ 0x10000fc0, 38, 35 },
		{ 0x10000fcc, 570, 18 },
		{ 0x10000fe4, 570, 18 },
		{ 0x10000ffc, 41, 17 },
		{ 0x10001008, 41, 35 },
		{ 0x10001014, 570, 18 },
		{ 0x1000102c, 572, 14 },
		{ 0x10001030, 46, 17 },
		{ 0x1000103c, 46, 35 },
		{ 0x10001048, 570, 18 },
		{ 0x10001060, 48, 17 },
		{ 0x10001074, 49, 17 },
		{ 0x10001080, 49, 35 },
		{ 0x1000108c, 570, 18 },
		{ 0x100010a4, 572, 14 },
		{ 0x100010a8, 570, 18 },
		{ 0x100010c0, 572, 14 },
		{ 0x100010c4, 570, 18 },
		{ 0x100010dc, 572, 14 },
		{ 0x100010e0, 570, 18 },
		{ 0x100010f8, 572, 14 },
		{ 0x100010fc, 600, 19 },
		{ 0x10001108, 450, 30 },
		{ 0x10001114, 49, 7 },
		{ 0x1000111c, 874, 2 },
		{ 0x10001128, 875, 51 },
		{ 0x1000112c, 600, 19 },
		{ 0x1000113c, 622, 25 },
		{ 0x10001144, 55, 13 },
		{ 0x10001154, 55, 23 },
		{ 0x1000115c, 34, 26 },
		{ 0x10001164, 32, 22 },
		{ 0x10001178, 34, 26 },
		{ 0x1000117c, 34, 17 },
		{ 0x10001180, 570, 18 },
		{ 0x100011ac, 50, 18 },
		{ 0x100011b4, 876, 2 },
		{ 0x100011c0, 877, 27 },
		{ 0x100011c4, 877, 23 },
		{ 0x100011e0, 877, 27 },
		{ 0x100011e4, 600, 19 },
		{ 0x100011f0, 450, 30 },
		{ 0x100011fc, 49, 7 },
		{ 0x10001204, 874, 2 },
		{ 0x10001210, 875, 51 },
		{ 0x10001214, 600, 19 },
		{ 0x10001224, 622, 25 },
		{ 0x1000122c, 600, 46 },
		{ 0x10001230, 50, 18 },
		{ 0x10001238, 876, 2 },
		{ 0x10001244, 877, 27 },
		{ 0x10001248, 877, 23 },
		{ 0x10001264, 877, 27 },
		{ 0x10001268, 58, 1 },
		{ 0x100012bc, 62, 22 },
		{ 0x100012c4, 66, 24 },
		{ 0x100012c8, 64, 26 },
		{ 0x100012d4, 66, 13 },
		{ 0x100012d8, 64, 9 },
		{ 0x100012e0, 62, 22 },
		{ 0x100012ec, 69, 5 },
		{ 0x100012f4, 70, 5 },
		{ 0x100012f8, 71, 1 },
		{ 0x10001308, 74, 1 },
		{ 0x10001314, 75, 5 },
		{ 0x10001334, 85, 24 },
		{ 0x10001338, 85, 13 },
		{ 0x10001348, 87, 17 },
		{ 0x10001350, 88, 22 },
		{ 0x1000136c, 75, 5 },
		{ 0x10001374, 99, 13 },
		{ 0x10001378, 99, 13 },
		{ 0x10001388, 101, 17 },
		{ 0x10001390, 102, 17 },
		{ 0x100013a8, 106, 13 },
		{ 0x100013ac, 107, 13 },
		{ 0x100013b4, 110, 1 },
		{ 0x100013bc, 78, 13 },
		{ 0x100013c0, 78, 13 },
		{ 0x100013d0, 80, 17 },
		{ 0x100013d8, 81, 22 },
		{ 0x100013e8, 92, 24 },
		{ 0x100013ec, 92, 13 },
		{ 0x100013fc, 94, 17 },
		{ 0x10001404, 95, 17 },
		{ 0x10001420, 137, 5 },
		{ 0x10001430, 136, 9 },
		{ 0x10001440, 137, 22 },
		{ 0x10001444, 139, 6 },
		{ 0x10001450, 140, 13 },
		{ 0x1000145c, 144, 5 },
		{ 0x10001460, 145, 1 },
		{ 0x10001474, 153, 5 },
		{ 0x10001480, 152, 9 },
		{ 0x10001490, 153, 5 },
		{ 0x10001498, 155, 2 },
		{ 0x100014a4, 155, 30 },
		{ 0x100014b0, 159, 5 },
		{ 0x100014b4, 160, 1 },
		{ 0x100014c8, 165, 1 },
		{ 0x100014cc, 168, 5 },
		{ 0x100014d0, 168, 5 },
		{ 0x100014d8, 170, 27 },
		{ 0x100014dc, 170, 9 },
		{ 0x100014ec, 167, 9 },
		{ 0x100014f4, 176, 41 },
		{ 0x10001500, 176, 41 },
		{ 0x1000150c, 174, 17 },
		{ 0x10001514, 176, 21 },
		{ 0x10001528, 176, 21 },
		{ 0x10001534, 176, 21 },
		{ 0x10001540, 176, 41 },
		{ 0x1000154c, 180, 14 },
		{ 0x10001550, 180, 14 },
		{ 0x10001560, 167, 9 },
		{ 0x10001568, 186, 41 },
		{ 0x10001574, 186, 41 },
		{ 0x10001580, 184, 34 },
		{ 0x10001588, 186, 21 },
		{ 0x1000159c, 186, 21 },
		{ 0x100015a8, 186, 21 },
		{ 0x100015b4, 186, 41 },
		{ 0x100015c0, 190, 32 },
		{ 0x100015c4, 268, 12 },
		{ 0x100015c8, 190, 14 },
		{ 0x100015dc, 196, 41 },
		{ 0x100015e8, 196, 41 },
		{ 0x100015f4, 194, 17 },
		{ 0x100015fc, 196, 21 },
		{ 0x10001610, 196, 21 },
		{ 0x1000161c, 196, 21 },
		{ 0x10001628, 196, 41 },
		{ 0x10001634, 201, 10 },
		{ 0x10001638, 201, 10 },
		{ 0x10001640, 203, 27 },
		{ 0x10001644, 203, 9 },
		{ 0x10001654, 167, 9 },
		{ 0x1000165c, 209, 41 },
		{ 0x10001668, 209, 41 },
		{ 0x10001674, 207, 34 },
		{ 0x1000167c, 209, 21 },
		{ 0x10001690, 209, 21 },
		{ 0x1000169c, 209, 21 },
		{ 0x100016a8, 209, 41 },
		{ 0x100016b4, 213, 14 },
		{ 0x100016b8, 213, 14 },
		{ 0x100016c8, 167, 9 },
		{ 0x100016d0, 219, 41 },
		{ 0x100016dc, 219, 41 },
		{ 0x100016e8, 217, 17 },
		{ 0x100016f0, 219, 21 },
		{ 0x10001704, 219, 21 },
		{ 0x10001710, 219, 21 },
		{ 0x1000171c, 219, 41 },
		{ 0x10001728, 223, 32 },
		{ 0x1000172c, 268, 12 },
		{ 0x10001730, 223, 14 },
		{ 0x10001744, 229, 41 },
		{ 0x10001750, 229, 41 },
		{ 0x1000175c, 227, 34 },
		{ 0x10001764, 229, 21 },
		{ 0x10001778, 229, 21 },
		{ 0x10001784, 229, 21 },
		{ 0x10001790, 229, 41 },
		{ 0x1000179c, 234, 10 },
		{ 0x100017a0, 268, 12 },
		{ 0x100017a4, 234, 10 },
		{ 0x100017ac, 236, 27 },
		{ 0x100017b0, 236, 9 },
		{ 0x100017c4, 242, 41 },
		{ 0x100017d0, 242, 41 },
		{ 0x100017dc, 240, 34 },
		{ 0x100017e4, 242, 21 },
		{ 0x100017f8, 242, 21 },
		{ 0x10001804, 242, 21 },
		{ 0x10001810, 242, 41 },
		{ 0x1000181c, 246, 14 },
		{ 0x10001820, 246, 14 },
		{ 0x10001830, 167, 9 },
		{ 0x10001838, 252, 41 },
		{ 0x10001844, 252, 41 },
		{ 0x10001850, 250, 34 },
		{ 0x10001858, 252, 21 },
		{ 0x1000186c, 252, 21 },
		{ 0x10001878, 252, 21 },
		{ 0x10001884, 252, 41 },
		{ 0x10001890, 256, 32 },
		{ 0x10001894, 268, 12 },
		{ 0x10001898, 256, 14 },
		{ 0x100018ac, 262, 41 },
		{ 0x100018b8, 262, 41 },
		{ 0x100018c4, 260, 34 },
		{ 0x100018cc, 262, 21 },
		{ 0x100018e0, 262, 21 },
		{ 0x100018ec, 262, 21 },
		{ 0x100018f8, 262, 41 },
		{ 0x10001904, 267, 5 },
		{ 0x1000190c, 270, 1 },
		{ 0x1000191c, 113, 1 },
		{ 0x1000194c, 115, 5 },
		{ 0x10001954, 115, 15 },
		{ 0x1000195c, 116, 26 },
		{ 0x10001960, 116, 37 },
		{ 0x10001964, 116, 9 },
		{ 0x10001974, 117, 32 },
		{ 0x10001978, 119, 18 },
		{ 0x10001984, 119, 40 },
		{ 0x1000198c, 119, 36 },
		{ 0x10001998, 119, 22 },
		{ 0x100019a0, 119, 54 },
		{ 0x100019ac, 119, 40 },
		{ 0x100019b4, 121, 36 },
		{ 0x100019c4, 122, 11 },
		{ 0x100019cc, 129, 1 },
		{ 0x100019f4, 126, 9 },
		{ 0x10001a0c, 11, 5 },
		{ 0x10001a10, 11, 5 },
		{ 0x10001a1c, 13, 1 },
		{ 0x10001a30, 17, 23 },
		{ 0x10001a34, 17, 5 },
		{ 0x10001a40, 19, 1 },
		{ 0x10001a54, 23, 5 },
		{ 0x10001a58, 23, 5 },
		{ 0x10001a64, 25, 10 },
		{ 0x10001a6c, 29, 1 },
		{ 0x10001a7c, 32, 5 },
		{ 0x10001a80, 32, 5 },
		{ 0x10001a8c, 34, 11 },
		{ 0x10001a94, 38, 1 },
		{ 0x10001aa4, 42, 16 },
		{ 0x10001aa8, 42, 5 },
		{ 0x10001ab4, 44, 1 },
		{ 0x10001ac8, 16, 1 },
		{ 0x10001ae4, 20, 16 },
		{ 0x10001aec, 22, 5 },
		{ 0x10001af8, 30, 13 },
		{ 0x10001b04, 31, 13 },
		{ 0x10001b10, 32, 22 },
		{ 0x10001b28, 40, 23 },
		{ 0x10001b3c, 42, 17 },
		{ 0x10001b44, 26, 9 },
		{ 0x10001b50, 26, 13 },
		{ 0x10001b54, 27, 9 },
		{ 0x10001b68, 28, 9 },
		{ 0x10001b6c, 28, 9 },
		{ 0x10001b78, 42, 16 },
		{ 0x10001b7c, 34, 14 },
		{ 0x10001b88, 36, 13 },
		{ 0x10001b94, 37, 24 },
		{ 0x10001ba0, 38, 13 },
		{ 0x10001bb4, 42, 17 },
		{ 0x10001bb8, 45, 1 },
		{ 0x10001be0, 45, 1 },
		{ 0x10001bf8, 74, 25 },
		{ 0x10001c28, 45, 1 },
		{ 0x10001c48, 0, 0 }
	};
	assert_source_files_eq(li->lines, RZ_ARRAY_SIZE(test_files), test_files);
	assert_source_lines_eq(li->lines, RZ_ARRAY_SIZE(test_lines), test_lines);
	rz_bin_dwarf_line_info_free(li);

#if 0
	RzList *line_list = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_ROWS);
	mu_assert_eq(rz_list_length(line_list), 1, "Amount of line information parse doesn't match");
	RzBinDwarfLineInfo *li = rz_list_first(line_list);
	mu_assert_eq(rz_list_length(li->rows), 475, "rows count");

	const RzBinSourceRow test_rows[] = {
		{ 0x10000ec4, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 30, 1 },
		{ 0x10000f18, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 31, 5 },
		{ 0x10000f18, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 31, 11 },
		{ 0x10000f28, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 32, 5 },
		{ 0x10000f28, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 32, 22 },
		{ 0x10000f2c, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 31, 11 },
		{ 0x10000f30, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 32, 13 },
		{ 0x10000f34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 34, 17 },
		{ 0x10000f38, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 53, 22 },
		{ 0x10000f44, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 38, 54 },
		{ 0x10000f44, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h", 335, 2 },
		{ 0x10000f44, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream", 570, 18 },
		{ 0x10000f5c, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream", 572, 14 },
		{ 0x10000f60, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 42, 22 },
		{ 0x10000f60, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h", 335, 2 },
		{ 0x10000f60, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream", 570, 18 }
	};
#endif

	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf3_aranges(void) {
	// The file's arange version is actually 2 but the format is the same as 3
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf3_many_comp_units.elf", &opt);
	mu_assert("couldn't open file", res);

	RzList *aranges = rz_bin_dwarf_parse_aranges(bin->cur);
	mu_assert_eq(rz_list_length(aranges), 2, "arange sets count");

	RzBinDwarfARangeSet *set = rz_list_get_n(aranges, 0);
	mu_assert_eq(set->unit_length, 60, "unit length");
	mu_assert_eq(set->version, 2, "version");
	mu_assert_eq(set->debug_info_offset, 0x0, "debug_info offset");
	mu_assert_eq(set->address_size, 8, "address size");
	mu_assert_eq(set->segment_size, 0, "segment size");
	mu_assert_eq(set->aranges_count, 3, "aranges count");
	RzBinDwarfARange ref_0[] = {
		{ 0x000000000000118a, 0x000000000000009e },
		{ 0x0000000000001228, 0x0000000000000013 },
		{ 0x0000000000000000, 0x0000000000000000 }
	};
	mu_assert_memeq((const ut8 *)set->aranges, (const ut8 *)&ref_0, sizeof(ref_0), "aranges contents");

	set = rz_list_get_n(aranges, 1);
	mu_assert_eq(set->unit_length, 188, "unit length");
	mu_assert_eq(set->version, 2, "version");
	mu_assert_eq(set->debug_info_offset, 0x22e, "debug_info offset");
	mu_assert_eq(set->address_size, 8, "address size");
	mu_assert_eq(set->segment_size, 0, "segment size");
	mu_assert_eq(set->aranges_count, 11, "aranges count");
	RzBinDwarfARange ref_1[] = {
		{ 0x000000000000123b, 0x000000000000008b },
		{ 0x00000000000012c6, 0x000000000000001d },
		{ 0x00000000000012e4, 0x000000000000002d },
		{ 0x0000000000001312, 0x000000000000002d },
		{ 0x0000000000001340, 0x000000000000002f },
		{ 0x0000000000001370, 0x0000000000000013 },
		{ 0x0000000000001384, 0x000000000000001d },
		{ 0x00000000000013a2, 0x000000000000001d },
		{ 0x00000000000013c0, 0x000000000000002f },
		{ 0x00000000000013f0, 0x0000000000000013 },
		{ 0x0000000000000000, 0x0000000000000000 }
	};
	mu_assert_memeq((const ut8 *)set->aranges, (const ut8 *)&ref_1, sizeof(ref_1), "aranges contents");

	rz_list_free(aranges);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_dwarf3_c_basic);
	mu_run_test(test_dwarf_cpp_empty_line_info);
	mu_run_test(test_dwarf2_cpp_many_comp_units);
	mu_run_test(test_dwarf3_cpp_basic);
	mu_run_test(test_dwarf3_cpp_many_comp_units);
	mu_run_test(test_dwarf4_cpp_many_comp_units);
	mu_run_test(test_dwarf4_multidir_comp_units);
	mu_run_test(test_big_endian_dwarf2);
	mu_run_test(test_dwarf3_aranges);
	return tests_passed != tests_run;
}

mu_main(all_tests)
