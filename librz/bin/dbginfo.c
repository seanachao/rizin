// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2021 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_bin.h>

// TODO: remove this!!!!!!!!!!!!!!!!!!!!!
RZ_API void rz_bin_source_row_free(RzBinSourceRow *row) {
	if (!row) {
		return;
	}
	free(row->file);
	free(row);
}
/// !!!!!!!!!!!!!!!!!!!!!!111!!!!!!!!!!!!!!!11

static void source_file_fini(RzBinSourceFile *sf, void *user) {
	free(sf->file);
}

RZ_API void rz_bin_source_line_info_builder_init(RzBinSourceLineInfoBuilder *builder) {
	rz_vector_init(&builder->files, sizeof(RzBinSourceFile), (RzVectorFree)source_file_fini, NULL);
	rz_vector_init(&builder->lines, sizeof(RzBinSourceLine), NULL, NULL);
}

RZ_API void rz_bin_source_line_info_builder_fini(RzBinSourceLineInfoBuilder *builder) {
	rz_vector_fini(&builder->files);
	rz_vector_fini(&builder->lines);
}

/**
 * \param file may be NULL, see RzBinSourceFile for exact meaning
 */
RZ_API void rz_bin_source_line_info_builder_push_file_sample(RzBinSourceLineInfoBuilder *builder, ut64 address, RZ_NULLABLE const char *file) {
	RzBinSourceFile *sample = rz_vector_push(&builder->files, NULL);
	if (!sample) {
		return;
	}
	sample->address = address;
	sample->file = file ? strdup(file) : NULL;
}

/**
 * \param line may be 0 or a positive line number, see RzBinSourceLine for exact meaning
 */
RZ_API void rz_bin_source_line_info_builder_push_line_sample(RzBinSourceLineInfoBuilder *builder, ut64 address, ut32 line, ut32 column) {
	RzBinSourceLine *sample = rz_vector_push(&builder->lines, NULL);
	if (!sample) {
		return;
	}
	sample->address = address;
	sample->line = line;
	sample->column = column;
}

static int file_cmp(const void *a, const void *b) {
	const RzBinSourceFile *fa = a;
	const RzBinSourceFile *fb = b;
	return fa->address < fb->address ? -1 : (fa->address > fb->address ? 1 : 0);
}

static int line_cmp(const void *a, const void *b) {
	const RzBinSourceLine *fa = a;
	const RzBinSourceLine *fb = b;
	return fa->address < fb->address ? -1 : (fa->address > fb->address ? 1 : 0);
}

RZ_API RzBinSourceLineInfo *rz_bin_source_line_info_builder_build_and_fini(RzBinSourceLineInfoBuilder *builder) {
	RzBinSourceLineInfo *r = RZ_NEW0(RzBinSourceLineInfo);
	if (!r) {
		goto err;
	}
	size_t initial_files_count = rz_vector_len(&builder->files); // final count may be less after removing dups
	if (initial_files_count) {
		r->files = RZ_NEWS0(RzBinSourceFile, initial_files_count);
		if (!r->files) {
			goto err_r;
		}
	}
	size_t initial_lines_count = rz_vector_len(&builder->lines); // final count may be less after removing dups
	if (initial_lines_count) {
		r->lines = RZ_NEWS0(RzBinSourceLine, rz_vector_len(&builder->lines));
		if (!r->lines) {
			goto err_files;
		}
	}

	// samples should be built in flat RzVector to avoid excessive small mallocs,
	// for sorting we use a pvector with references into our flat vectors (after flushing them).

	if (initial_files_count) {
		RzPVector sorter;
		rz_pvector_init(&sorter, NULL);
		RzBinSourceFile *initial_files = rz_vector_flush(&builder->files);
		rz_pvector_reserve(&sorter, initial_files_count);
		r->files_count = 0;
		for (size_t i = 0; i < initial_files_count; i++) {
			rz_pvector_push(&sorter, &initial_files[i]);
		}
		rz_pvector_sort(&sorter, file_cmp);
		ut64 dont_close_here = UT64_MAX; // to avoid closing on valid positions
		for (size_t i = 0; i < initial_files_count; i++) {
			RzBinSourceFile *new_file = rz_pvector_at(&sorter, i);
			if (!r->files_count || r->files[r->files_count - 1].address != new_file->address) {
				// new address, just move this entry to the final array, ...
				if (r->files_count) {
					RzBinSourceFile *prev = &r->files[r->files_count - 1];
					if ((!prev->file && !new_file->file) || (prev->file && new_file->file && !strcmp(prev->file, new_file->file))) {
						// ... unless it is identical to the previous
						dont_close_here = new_file->address;
						free(new_file->file);
						continue;
					}
				}
				if (!new_file->file && dont_close_here != UT64_MAX && new_file->address == dont_close_here) {
					// extended record from above with explicit filename
					continue;
				}
				r->files[r->files_count++] = *new_file;
			} else if (new_file->file) {
				// same address as the previous and we are not a closing sample, decide how to resolve this...
				RzBinSourceFile *prev = &r->files[r->files_count - 1];
				if (!prev->file) {
					// we bring the string!
					if (r->files_count >= 2 && r->files[r->files_count - 2].file && !strcmp(r->files[r->files_count - 2].file, new_file->file)) {
						// but actually we just cancel out the previous closing entry and
						// continue the non-closing one before that.
						r->files_count--;
						free(new_file->file);
					} else {
						prev->file = new_file->file;
					}
				} else if (strcmp(prev->file, new_file->file) < 0) {
					// both have a string. This should not happen with debug info that actually makes sense,
					// but it's supplied from outside so we never know.
					// strcmp is used to resolve non-determinism from the unstable (possibly randomized) quicksort.
					free(prev->file);
					prev->file = new_file->file;
				} else {
					// same as above but we keep the other string.
					free(new_file->file);
				}
			}
		}
		if (r->files_count < initial_files_count) {
			size_t news = r->files_count * sizeof(RzBinSourceFile);
			if (news / sizeof(RzBinSourceFile) == r->files_count) {
				RzBinSourceFile *nf = realloc(r->files, news);
				if (nf) {
					r->files = nf;
				}
			}
		}
		rz_pvector_fini(&sorter);
		free(initial_files); // no need to do anything with the strings inside, they are all moved or freed.
	}

	if (initial_lines_count) {
		RzPVector sorter;
		rz_pvector_init(&sorter, NULL);
		RzBinSourceLine *initial_lines = rz_vector_flush(&builder->lines);
		rz_pvector_reserve(&sorter, initial_lines_count);
		r->lines_count = 0;
		for (size_t i = 0; i < initial_lines_count; i++) {
			rz_pvector_push(&sorter, &initial_lines[i]);
		}
		rz_pvector_sort(&sorter, line_cmp);
		for (size_t i = 0; i < initial_lines_count; i++) {
			RzBinSourceLine *new_line = rz_pvector_at(&sorter, i);
			if (i == 0 || r->lines[r->lines_count - 1].address != new_line->address) {
				// new address, just move this entry to the final array
				r->lines[r->lines_count++] = *new_line;
			} else if (new_line->line) {
				// same address as the previous and we are not a closing sample, decide how to resolve this...
				RzBinSourceLine *prev = &r->lines[r->lines_count - 1];
				if (!prev->line) {
					// we supply the line!
					prev->line = new_line->line;
				} else if (new_line->line > prev->line) {
					// both have a non-closing line entry. This should not happen with debug info that actually makes sense,
					// but it's supplied from outside so we never know.
					// comparison is used to resolve non-determinism from the unstable (possibly randomized) quicksort.
					*prev = *new_line;
				}
			}
		}
		if (r->lines_count < initial_lines_count) {
			size_t news = r->lines_count * sizeof(RzBinSourceLine);
			if (news / sizeof(RzBinSourceLine) == r->lines_count) {
				RzBinSourceLine *nf = realloc(r->lines, news);
				if (nf) {
					r->lines = nf;
				}
			}
		}
		rz_pvector_fini(&sorter);
		free(initial_lines);
	}

	rz_bin_source_line_info_builder_fini(builder);
	return r;
err_files:
	free(r->files);
err_r:
	free(r);
err:
	rz_bin_source_line_info_builder_fini(builder);
	return NULL;
}

RZ_API void rz_bin_source_line_info_free(RzBinSourceLineInfo *sli) {
	if (!sli) {
		return;
	}
	free(sli->lines);
	free(sli->files);
	free(sli);
}

#define binary_search_addr(r, prefix, addr) \
	if (prefix##_count) { \
		size_t l = 0; \
		size_t h = prefix##_count; \
		while (l < h - 1) { \
			size_t m = l + ((h - l) >> 1); \
			if (addr < prefix[m].address) { \
				h = m; \
			} else { \
				l = m; \
			} \
		} \
		r = (l < prefix##_count && prefix[l].address <= addr) ? &prefix[l] : NULL; \
	}

RZ_API const RzBinSourceFile *rz_bin_source_line_info_get_file_at(RzBinSourceLineInfo *sli, ut64 addr) {
	RzBinSourceFile *r = NULL;
	binary_search_addr(r, sli->files, addr);
	if (r && r->file) {
		// r->file == NULL would mean it's a closing entry which we don't want to return
		return r;
	}
	return NULL;
}

RZ_API const RzBinSourceLine *rz_bin_source_line_info_get_line_at(RzBinSourceLineInfo *sli, ut64 addr) {
	RzBinSourceLine *r = NULL;
	binary_search_addr(r, sli->lines, addr);
	if (r && r->line) {
		// r->line == 0 would mean it's a closing entry which we don't want to return
		return r;
	}
	return NULL;
}

RZ_API bool rz_bin_addr2line(RzBin *bin, ut64 addr, char *file, int len, int *line) {
	rz_return_val_if_fail(bin, false);
	RzBinFile *binfile = rz_bin_cur(bin);
	RzBinObject *o = rz_bin_cur_object(bin);
	RzBinPlugin *cp = rz_bin_file_cur_plugin(binfile);
	ut64 baddr = rz_bin_get_baddr(bin);
	if (cp && cp->dbginfo) {
		if (o && addr >= baddr && addr < baddr + bin->cur->o->size) {
			if (cp->dbginfo->get_line) {
				return cp->dbginfo->get_line(
					bin->cur, addr, file, len, line);
			}
		}
	}
	return false;
}

RZ_API char *rz_bin_addr2text(RzBin *bin, ut64 addr, int origin) {
	rz_return_val_if_fail(bin, NULL);
	char file[4096];
	int line;
	char *out = NULL, *out2 = NULL;
	char *file_nopath = NULL;
	if (!bin->cur) {
		return NULL;
	}
	char *key = rz_str_newf("0x%" PFMT64x, addr);
	char *file_line = sdb_get(bin->cur->sdb_addrinfo, key, 0);
	if (file_line) {
		char *token = strchr(file_line, '|');
		if (token) {
			*token++ = 0;
			line = atoi(token);
			out = rz_file_slurp_line(file_line, line, 0);
			*token++ = ':';
		} else {
			return file_line;
		}
	}
	free(key);
	if (out) {
		if (origin > 1) {
			file_nopath = file_line;
		} else {
			file_nopath = strrchr(file_line, '/');
			if (file_nopath) {
				file_nopath++;
			} else {
				file_nopath = file_line;
			}
		}
		if (origin) {
			char *res = rz_str_newf("%s:%d%s%s",
				file_nopath ? file_nopath : "",
				line, file_nopath ? " " : "",
				out ? out : "");
			free(out);
			out = res;
		}
		free(file_line);
		return out;
	}
	RZ_FREE(file_line);

	file[0] = 0;
	if (rz_bin_addr2line(bin, addr, file, sizeof(file), &line)) {
		if (bin->srcdir && *bin->srcdir) {
			char *slash = strrchr(file, '/');
			char *nf = rz_str_newf("%s/%s", bin->srcdir, slash ? slash + 1 : file);
			strncpy(file, nf, sizeof(file) - 1);
			free(nf);
		}
		// TODO: this is slow. must use a cached pool of mapped files and line:off entries
		out = rz_file_slurp_line(file, line, 0);
		if (!out) {
			if (origin > 1) {
				file_nopath = file;
			} else {
				file_nopath = strrchr(file, '/');
				if (file_nopath) {
					file_nopath++;
				} else {
					file_nopath = file;
				}
			}
			return rz_str_newf("%s:%d", file_nopath ? file_nopath : "", line);
		}
		out2 = malloc((strlen(file) + 64 + strlen(out)) * sizeof(char));
		if (origin > 1) {
			file_nopath = NULL;
		} else {
			file_nopath = strrchr(file, '/');
		}
		if (origin) {
			snprintf(out2, strlen(file) + 63 + strlen(out), "%s:%d%s%s",
				file_nopath ? file_nopath + 1 : file, line, *out ? " " : "", out);
		} else {
			snprintf(out2, 64, "%s", out);
		}
		free(out);
	}
	return out2;
}

RZ_API char *rz_bin_addr2fileline(RzBin *bin, ut64 addr) {
	rz_return_val_if_fail(bin, NULL);
	char file[1024];
	int line = 0;

	if (rz_bin_addr2line(bin, addr, file, sizeof(file) - 1, &line)) {
		char *file_nopath = strrchr(file, '/');
		return rz_str_newf("%s:%d", file_nopath ? file_nopath + 1 : file, line);
	}
	return NULL;
}
