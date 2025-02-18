// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <string.h>
#include <rz_io.h>
#include <rz_main.h>
#include <rz_hash.h>
#include <rz_util/rz_print.h>
#include <rz_util.h>
#include <rz_crypto.h>

#define RZ_CRYPTO_NBITS (sizeof(RzCryptoSelector) * 8)

typedef enum {
	RZ_HASH_MODE_STANDARD = 0,
	RZ_HASH_MODE_JSON,
	RZ_HASH_MODE_RANDOMART,
	RZ_HASH_MODE_QUIET,
	RZ_HASH_MODE_VERY_QUIET,
} RzHashMode;

typedef enum {
	RZ_HASH_OP_UNKNOWN = 0,
	RZ_HASH_OP_ERROR,
	RZ_HASH_OP_HELP,
	RZ_HASH_OP_USAGE,
	RZ_HASH_OP_VERSION,
	RZ_HASH_OP_LIST_ALGO,
	RZ_HASH_OP_HASH,
	RZ_HASH_OP_DECRYPT,
	RZ_HASH_OP_ENCRYPT,
} RzHashOp;

typedef struct {
	ut64 from;
	ut64 to;
} RzHashOffset;

typedef struct rz_hash_context {
	bool little_endian;
	bool show_blocks;
	bool use_stdin;
	char *algorithm;
	char *compare;
	char *iv;
	char *input;
	const char **files;
	ut32 nfiles;
	RzHashSeed seed;
	RzHashMode mode;
	RzHashOffset offset;
	RzHashOp operation;
	ut64 iterate;
	ut64 block_size;
	/* Output here */
	PJ *pj;
	bool newline;
} RzHashContext;

typedef bool (*RzHashRun)(RzHashContext *ctx, RzIO *io, const char *filename);

static void rz_hash_show_help(bool usage_only) {
	printf("Usage: rz-hash [-vhBkjLq] [-b S] [-a A] [-c H] [-E A] [-D A] [-s S] [-x S] [-f O] [-t O] [files|-] ...\n");
	if (usage_only) {
		return;
	}
	printf(
		" -v          Shows version\n"
		" -h          Shows this help page\n"
		" -           Input read from stdin instead from a file\n"
		" -a algo     Hash algorithm to use and you can specify multiple ones by\n"
		"             appending a comma (example: sha1,md4,md5,sha256)\n"
		" -B          Outputs the calculated value for each block\n"
		" -b size     Sets the block size\n"
		" -c value    Compare calculated value with a given one (hexadecimal)\n"
		" -e endian   Sets the endianness (default: 'big' accepted: 'big' or 'little')\n"
		" -D algo     Decrypt the given input; use -S to set key and -I to set IV (if needed)\n"
		" -E algo     Encrypt the given input; use -S to set key and -I to set IV (if needed)\n"
		" -f from     Starts the calculation at given offset\n"
		" -t to       Stops the calculation at given offset\n"
		" -I iv       Sets the initialization vector (IV)\n"
		" -i times    Repeat the calculation N times\n"
		" -j          Outputs the result as a JSON structure\n"
		" -k          Outputs the calculated value using openssh's randomkey algorithm\n"
		" -L          List all algorithms\n"
		" -q          Sets quiet mode (use -qq to get only the calculated value)\n"
		" -S seed/key Sets the seed for -a and the key for -E/-D, use '^' to append it before\n"
		"             the input, use '@' prefix to load it from a file and '-' from read it\n"
		"             from stdin (you can combine them)\n"
		" -s string   Input read from a zero-terminated string instead from a file\n"
		" -x hex      Input read from a hexadecimal value instead from a file\n"
		"\n"
		"             All the inputs (besides -s/-x/-c) can be hexadecimal or strings\n"
		"             if 's:' prefix is specified\n");
}

static void rz_hash_show_algorithms() {
	const char *name;
	for (ut64 i = 0; i < RZ_HASH_NBITS; i++) {
		name = rz_hash_name(1ull << i);
		if (RZ_STR_ISEMPTY(name)) {
			continue;
		}
		printf("h  %s\n", name);
	}

	for (ut64 i = 0; i < RZ_CRYPTO_NBITS; i++) {
		name = rz_crypto_codec_name(1ul << i);
		if (RZ_STR_ISEMPTY(name)) {
			continue;
		}
		printf("e  %s\n", name);
	}

	for (ut64 i = 0; i < RZ_CRYPTO_NBITS; i++) {
		name = rz_crypto_name(1ul << i);
		if (RZ_STR_ISEMPTY(name)) {
			continue;
		}
		printf("c  %s\n", name);
	}
}

#define rz_hash_error(x, o, f, ...) \
	(x)->operation = o; \
	RZ_LOG_ERROR("rz-hash: error, " f, ##__VA_ARGS__); \
	return;

#define rz_hash_set_val(x, k, d, v) \
	do { \
		if ((k) != (d)) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "invalid combination of arguments for '-%c' (expected " #d " but found something else)\n", c); \
		} \
		(k) = (v); \
	} while (0)

#define rz_hash_ctx_set_val(x, k, d, v) \
	do { \
		if ((x)->k != (d)) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "invalid combination of arguments for '-%c' (expected " #d " but found something else)\n", c); \
		} \
		(x)->k = (v); \
	} while (0)

#define rz_hash_ctx_set_bool(x, k, i, t, f) \
	do { \
		if (i && !strcmp(i, t)) { \
			(x)->k = true; \
		} else if (i && !strcmp(i, f)) { \
			(x)->k = false; \
		} else { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "expected '%s' or '%s' but got '%s'\n", t, f, i); \
		} \
	} while (0)

#define rz_hash_ctx_set_quiet(x) \
	do { \
		if ((x)->mode == RZ_HASH_MODE_STANDARD) { \
			(x)->mode = RZ_HASH_MODE_QUIET; \
		} else if ((x)->mode == RZ_HASH_MODE_QUIET) { \
			(x)->mode = RZ_HASH_MODE_VERY_QUIET; \
		} else if ((x)->mode == RZ_HASH_MODE_JSON) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "can't be quiet when json mode is selected\n"); \
		} else if ((x)->mode == RZ_HASH_MODE_RANDOMART) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "can't be quiet when openssh mode is selected\n"); \
		} \
	} while (0)

#define rz_hash_ctx_set_signed(x, k, i) \
	do { \
		(x)->k = strtoll((i), NULL, 0); \
		if ((x)->k < 1) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "argument must be > 0\n"); \
		} \
	} while (0)

#define rz_hash_ctx_set_unsigned(x, k, i) \
	do { \
		(x)->k = strtoull((i), NULL, 0); \
		if ((x)->k < 1) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "argument must be > 0\n"); \
		} \
	} while (0)

#define rz_hash_ctx_set_input(x, k, s, h) \
	do { \
		if ((x)->k) { \
			rz_hash_error(x, RZ_HASH_OP_UNKNOWN, "invalid combination of arguments for '-%c'\n", c); \
		} else if (h || strlen(s) < 1) { \
			(x)->k = strdup(s); \
		} else { \
			(x)->k = rz_str_newf("s:%s", s); \
		} \
	} while (0)

#define rz_hash_ctx_set_mode(x, m)   rz_hash_ctx_set_val(x, mode, RZ_HASH_MODE_STANDARD, m)
#define rz_hash_ctx_set_op(x, o)     rz_hash_ctx_set_val(x, operation, RZ_HASH_OP_UNKNOWN, o)
#define rz_hash_ctx_set_str(x, k, s) rz_hash_ctx_set_val(x, k, NULL, strdup(s))

static bool rz_hash_parse_string(const char *option, const char *string, ut8 **buffer, size_t *bufsize) {
	char *sstdin = NULL;
	int stringlen = 0;
	if (!strcmp(string, "-")) {
		string = sstdin = rz_stdin_slurp(&stringlen);
	} else {
		stringlen = strlen(string);
	}
	if (stringlen < 1 || !string) {
		RZ_LOG_ERROR("rz-hash: error, option %s is empty.\n", option);
		free(sstdin);
		return false;
	}

	ut8 *b = (ut8 *)malloc(stringlen + 1);
	if (!b) {
		RZ_LOG_ERROR("rz-hash: error, failed to allocate string in memory.\n");
		free(sstdin);
		return false;
	}

	memcpy(b, string, stringlen);
	b[stringlen] = 0;
	stringlen = rz_str_unescape((char *)b);

	*buffer = b;
	*bufsize = stringlen;
	free(sstdin);

	return true;
}

static bool rz_hash_parse_hexadecimal(const char *option, const char *hexadecimal, ut8 **buffer, size_t *bufsize) {
	char *sstdin = NULL;
	int hexlen = 0;
	if (!strcmp(hexadecimal, "-")) {
		hexadecimal = sstdin = rz_stdin_slurp(&hexlen);
	} else {
		hexlen = strlen(hexadecimal);
	}

	if (hexlen < 1 || !hexadecimal) {
		RZ_LOG_ERROR("rz-hash: error, option %s is empty.\n", option);
		return false;
	} else if (hexlen & 1) {
		RZ_LOG_ERROR("rz-hash: error, option %s is not a valid hexadecimal (len is not pair: %d).\n", option, hexlen);
		return false;
	}
	*buffer = NULL;
	st64 binlen = hexlen >> 1;
	ut8 *b = (ut8 *)malloc(binlen);
	if (b) {
		*bufsize = rz_hex_str2bin(hexadecimal, b);
		if (*bufsize < 1) {
			RZ_LOG_ERROR("rz-hash: error, option %s is not a valid hexadecimal.\n", option);
			free(b);
			free(sstdin);
			return false;
		}
		*buffer = b;
	}

	free(sstdin);
	return true;
}

static void rz_hash_parse_cmdline(int argc, const char **argv, RzHashContext *ctx) {
	const char *seed = NULL;

	memset((void *)ctx, 0, sizeof(RzHashContext));

	RzGetopt opt;
	int c;
	rz_getopt_init(&opt, argc, argv, "jD:e:vE:a:i:I:S:s:x:b:nBhf:t:kLqc:");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'q': rz_hash_ctx_set_quiet(ctx); break;
		case 'i': rz_hash_ctx_set_signed(ctx, iterate, opt.arg); break;
		case 'j': rz_hash_ctx_set_mode(ctx, RZ_HASH_MODE_JSON); break;
		case 'S': rz_hash_set_val(ctx, seed, NULL, opt.arg); break;
		case 'I': rz_hash_ctx_set_str(ctx, iv, opt.arg); break;
		case 'D':
			rz_hash_ctx_set_str(ctx, algorithm, opt.arg);
			rz_hash_ctx_set_op(ctx, RZ_HASH_OP_DECRYPT);
			break;
		case 'E':
			rz_hash_ctx_set_str(ctx, algorithm, opt.arg);
			rz_hash_ctx_set_op(ctx, RZ_HASH_OP_ENCRYPT);
			break;
		case 'L': rz_hash_ctx_set_op(ctx, RZ_HASH_OP_LIST_ALGO); break;
		case 'e': rz_hash_ctx_set_bool(ctx, little_endian, opt.arg, "little", "big"); break;
		case 'k': rz_hash_ctx_set_mode(ctx, RZ_HASH_MODE_RANDOMART); break;
		case 'a':
			rz_hash_ctx_set_str(ctx, algorithm, opt.arg);
			rz_hash_ctx_set_op(ctx, RZ_HASH_OP_HASH);
			break;
		case 'B': ctx->show_blocks = true; break;
		case 'b': rz_hash_ctx_set_unsigned(ctx, block_size, opt.arg); break;
		case 'f': rz_hash_ctx_set_unsigned(ctx, offset.from, opt.arg); break;
		case 't': rz_hash_ctx_set_unsigned(ctx, offset.to, opt.arg); break;
		case 'v': ctx->operation = RZ_HASH_OP_VERSION; break;
		case 'h': ctx->operation = RZ_HASH_OP_HELP; break;
		case 's': rz_hash_ctx_set_input(ctx, input, opt.arg, false); break;
		case 'x': rz_hash_ctx_set_input(ctx, input, opt.arg, true); break;
		case 'c': rz_hash_ctx_set_str(ctx, compare, opt.arg); break;
		default:
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "unknown flag '%c'\n", c);
		}
	}

	if (ctx->operation == RZ_HASH_OP_HELP ||
		ctx->operation == RZ_HASH_OP_VERSION ||
		ctx->operation == RZ_HASH_OP_LIST_ALGO) {
		return;
	}

	if (opt.ind >= argc && !ctx->input) {
		ctx->operation = RZ_HASH_OP_USAGE;
		return;
	}

	if (!ctx->input && !strcmp(argv[argc - 1], "-")) {
		ctx->use_stdin = true;
	} else {
		ctx->files = RZ_NEWS(const char *, argc - opt.ind);
		if (!ctx->files) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "failed to allocate file array memory.\n");
		}
		ctx->nfiles = 0;
		for (int i = opt.ind; i < argc; ++i) {
			if (IS_NULLSTR(argv[i])) {
				rz_hash_error(ctx, RZ_HASH_OP_ERROR, "cannot open a file without a name.\n");
			}
			if (rz_file_is_directory(argv[i])) {
				rz_hash_error(ctx, RZ_HASH_OP_ERROR, "cannot open directories (%s).\n", argv[i]);
			}
			ctx->files[ctx->nfiles++] = argv[i];
		}
	}

	if (ctx->nfiles < 1 && !ctx->use_stdin && !ctx->input) {
		ctx->operation = RZ_HASH_OP_USAGE;
		return;
	}

	if (ctx->operation == RZ_HASH_OP_ENCRYPT || ctx->operation == RZ_HASH_OP_DECRYPT) {
		if (!seed && strncmp("base", ctx->algorithm, 4) && strcmp("punycode", ctx->algorithm)) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -S is required for algorithm '%s'.\n", ctx->algorithm);
		}
		if (ctx->compare) {
			ssize_t len = strlen(ctx->compare);
			if (!strncmp(ctx->algorithm, "base", 4)) {
				rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -c is incompatible with -E or -D with algorithm base64 or base91.\n");
			} else if (strchr(ctx->algorithm, ',')) {
				rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -c incompatible with multiple algorithms.\n");
			} else if (len < 1 || c & 1) {
				rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -c value length is not multiple of 2 (expected hexadecimal value).\n");
			}
		}
		if (ctx->show_blocks) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -B is incompatible with -E/-D.\n");
		}
		if (ctx->mode == RZ_HASH_MODE_RANDOMART) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -k is incompatible with -E/-D.\n");
		}
	} else if (ctx->operation == RZ_HASH_OP_HASH) {
		if (ctx->iv) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -I is incompatible with -a; use -S to define a seed.\n");
		}
		if (ctx->show_blocks && ctx->compare) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -B is incompatible with -c.\n");
		}
		if (ctx->mode == RZ_HASH_MODE_RANDOMART && ctx->compare) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -c is incompatible with -k.\n");
		}
		if (ctx->mode == RZ_HASH_MODE_RANDOMART && strchr(ctx->algorithm, ',')) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -a with multiple algorithms is incompatible with -k.\n");
		}
	}

	if (ctx->offset.from && ctx->offset.to && ctx->offset.from >= ctx->offset.to) {
		rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -f value (%" PFMT64u ") is greater or equal to -t value (%" PFMT64u ").\n", ctx->offset.from, ctx->offset.to);
	}
	if (ctx->block_size && ctx->offset.from && ctx->offset.to && (ctx->offset.to - ctx->offset.from) % ctx->block_size) {
		rz_hash_error(ctx, RZ_HASH_OP_ERROR, "range between %" PFMT64u " and %" PFMT64u " is not a multiple of %" PFMT64u ".\n", ctx->offset.from, ctx->offset.to, ctx->block_size);
	}

	if (seed) {
		if (seed[0] == '^') {
			seed++;
			ctx->seed.as_prefix = true;
		}
		ssize_t seedlen = strlen(seed);
		if (seedlen < 1) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "option -S is empty.\n");
		}
		if (!strcmp(seed, "-")) {
			int stdinlen = 0;
			ctx->seed.buf = (ut8 *)rz_stdin_slurp(&stdinlen);
			ctx->seed.len = stdinlen;
		} else if (seed[0] == '@') {
			ctx->seed.buf = (ut8 *)rz_file_slurp(seed + 1, &ctx->seed.len);
		} else if (!strncmp(seed, "s:", 2)) {
			if (!rz_hash_parse_string("-S", seed + 2, &ctx->seed.buf, &ctx->seed.len)) {
				ctx->operation = RZ_HASH_OP_ERROR;
				return;
			}
		} else {
			if (!rz_hash_parse_hexadecimal("-S", seed, &ctx->seed.buf, &ctx->seed.len)) {
				ctx->operation = RZ_HASH_OP_ERROR;
				return;
			}
		}
		if (!ctx->seed.buf) {
			rz_hash_error(ctx, RZ_HASH_OP_ERROR, "failed to allocate seed memory.\n");
		}
	}

	if (!ctx->block_size) {
		ctx->block_size = 0x1000;
	}
}

static void rz_hash_context_fini(RzHashContext *ctx) {
	free(ctx->algorithm);
	free(ctx->compare);
	free(ctx->iv);
	free(ctx->input);
	free(ctx->files);
	free(ctx->seed.buf);
	pj_free(ctx->pj);
}

static RzIODesc *rz_hash_context_create_desc_io_stdin(RzIO *io) {
	RzIODesc *desc = NULL;
	int size;
	char *uri = NULL;
	ut8 *buffer = NULL;

	buffer = (ut8 *)rz_stdin_slurp(&size);
	if (size < 1 || !buffer) {
		goto rz_hash_context_create_desc_io_stdin_end;
	}

	uri = rz_str_newf("malloc://%d", size);
	if (!uri) {
		rz_warn_if_reached();
		goto rz_hash_context_create_desc_io_stdin_end;
	}

	desc = rz_io_open_nomap(io, uri, RZ_PERM_R, 0);
	if (!desc) {
		RZ_LOG_ERROR("rz-hash: error, cannot open malloc://%d\n", size);
		goto rz_hash_context_create_desc_io_stdin_end;
	}

	if (rz_io_pwrite_at(io, 0, buffer, size) != size) {
		RZ_LOG_ERROR("rz-hash: error, cannot write into malloc://%d buffer\n", size);
		rz_io_desc_close(desc);
		desc = NULL;
		goto rz_hash_context_create_desc_io_stdin_end;
	}

rz_hash_context_create_desc_io_stdin_end:
	free(buffer);
	free(uri);
	return desc;
}

static RzIODesc *rz_hash_context_create_desc_io_string(RzIO *io, const char *input) {
	RzIODesc *desc = NULL;
	char *uri = NULL;
	ut8 *buffer = NULL;
	size_t size;

	bool is_string = !strncmp(input, "s:", 2);

	if (is_string) {
		if (!rz_hash_parse_string("-s", input + 2, &buffer, &size)) {
			goto rz_hash_context_create_desc_io_string_end;
		}
	} else {
		if (!rz_hash_parse_hexadecimal("-x", input, &buffer, &size)) {
			goto rz_hash_context_create_desc_io_string_end;
		}
	}
	if (!buffer || (!is_string && size < 1)) {
		rz_warn_if_reached();
		goto rz_hash_context_create_desc_io_string_end;
	} else if (is_string && size < 1) {
		goto rz_hash_context_create_desc_io_string_end;
	}

	uri = rz_str_newf("malloc://%lu", size);
	if (!uri) {
		rz_warn_if_reached();
		goto rz_hash_context_create_desc_io_string_end;
	}

	desc = rz_io_open_nomap(io, uri, RZ_PERM_R, 0);
	if (!desc) {
		RZ_LOG_ERROR("rz-hash: error, cannot open malloc://%lu\n", size);
		goto rz_hash_context_create_desc_io_string_end;
	}

	if (rz_io_pwrite_at(io, 0, buffer, size) != size) {
		RZ_LOG_ERROR("rz-hash: error, cannot write into malloc://%lu buffer\n", size);
		rz_io_desc_close(desc);
		desc = NULL;
		goto rz_hash_context_create_desc_io_string_end;
	}

rz_hash_context_create_desc_io_string_end:
	free(buffer);
	free(uri);
	return desc;
}

static bool rz_hash_context_run(RzHashContext *ctx, RzHashRun run) {
	bool result = false;
	RzIODesc *desc = NULL;

	RzIO *io = rz_io_new();
	if (!io) {
		rz_warn_if_reached();
		return false;
	}

	if (ctx->mode == RZ_HASH_MODE_JSON) {
		ctx->pj = pj_new();
		if (!ctx->pj) {
			RZ_LOG_ERROR("rz-hash: error, failed to allocate JSON memory.\n");
			goto rz_hash_context_run_end;
		}
		pj_o(ctx->pj);
	}
	if (ctx->use_stdin) {
		desc = rz_hash_context_create_desc_io_stdin(io);
		if (!desc) {
			RZ_LOG_ERROR("rz-hash: error, cannot read stdin\n");
			goto rz_hash_context_run_end;
		}
		if (ctx->mode == RZ_HASH_MODE_JSON) {
			pj_ka(ctx->pj, "stdin");
		}
		if (!run(ctx, io, "stdin")) {
			goto rz_hash_context_run_end;
		}
		if (ctx->mode == RZ_HASH_MODE_JSON) {
			pj_end(ctx->pj);
		}
	} else if (ctx->input) {
		if (strlen(ctx->input) > 0) {
			desc = rz_hash_context_create_desc_io_string(io, ctx->input);
			if (!desc) {
				RZ_LOG_ERROR("rz-hash: error, cannot read string\n");
				goto rz_hash_context_run_end;
			}
		}
		if (ctx->mode == RZ_HASH_MODE_JSON) {
			pj_ka(ctx->pj, !strncmp(ctx->input, "s:", 2) ? "string" : "hexadecimal");
		}
		if (!run(ctx, io, !strncmp(ctx->input, "s:", 2) ? "string" : "hexadecimal")) {
			goto rz_hash_context_run_end;
		}
		if (ctx->mode == RZ_HASH_MODE_JSON) {
			pj_end(ctx->pj);
		}
	} else {
		for (ut32 i = 0; i < ctx->nfiles; ++i) {
			desc = rz_io_open_nomap(io, ctx->files[i], RZ_PERM_R, 0);
			if (!desc) {
				RZ_LOG_ERROR("rz-hash: error, cannot open file '%s'\n", ctx->files[i]);
				goto rz_hash_context_run_end;
			}
			if (ctx->mode == RZ_HASH_MODE_JSON) {
				pj_ka(ctx->pj, ctx->files[i]);
			}
			if (!run(ctx, io, ctx->files[i])) {
				goto rz_hash_context_run_end;
			}
			if (ctx->mode == RZ_HASH_MODE_JSON) {
				pj_end(ctx->pj);
			}
			rz_io_desc_close(desc);
			desc = NULL;
		}
	}
	if (ctx->mode == RZ_HASH_MODE_JSON) {
		pj_end(ctx->pj);
		printf("%s\n", pj_string(ctx->pj));
	}
	result = true;

rz_hash_context_run_end:
	rz_io_desc_close(desc);
	rz_io_free(io);
	return result;
}

static void rz_hash_print_crypto(RzHashContext *ctx, const char *hname, const ut8 *buffer, int len, ut64 from, ut64 to) {
	char *value = ctx->operation == RZ_HASH_OP_ENCRYPT ? malloc(len * 2 + 1) : malloc(len + 1);
	if (!value) {
		RZ_LOG_ERROR("rz-hash: error, cannot allocate value memory\n");
		return;
	}

	if (ctx->operation == RZ_HASH_OP_ENCRYPT) {
		for (int i = 0, bsize; i < len; i++) {
			bsize = (len - i) * 2 + 1;
			snprintf(value + (i * 2), bsize, "%02x", buffer[i]);
		}
	} else {
		memcpy(value, buffer, len);
		value[len] = 0;
	}

	switch (ctx->mode) {
	case RZ_HASH_MODE_JSON:
		pj_kn(ctx->pj, "from", from);
		pj_kn(ctx->pj, "to", to);
		pj_ks(ctx->pj, "name", hname);
		pj_ks(ctx->pj, "value", value);
		break;
	case RZ_HASH_MODE_RANDOMART:
	case RZ_HASH_MODE_STANDARD:
		printf("0x%08" PFMT64x "-0x%08" PFMT64x " %s: ", from, to, hname);
		fflush(stdout);
		if (write(1, buffer, len) != len) {
			RZ_LOG_ERROR("rz-hash: error, cannot write on stdout\n");
		}
		printf("\n");
		break;
	case RZ_HASH_MODE_QUIET:
		printf("%s: ", hname);
		fflush(stdout);
		if (write(1, buffer, len) != len) {
			RZ_LOG_ERROR("rz-hash: error, cannot write on stdout\n");
		}
		printf("\n");
		break;
	case RZ_HASH_MODE_VERY_QUIET:
		if (write(1, buffer, len) != len) {
			RZ_LOG_ERROR("rz-hash: error, cannot write on stdout\n");
		}
		break;
	}
	free(value);
}

static void rz_hash_print_digest(RzHashContext *ctx, RzHash *hctx, const char *hname, const ut8 *buffer, int len, ut64 from, ut64 to, const char *filename) {
	bool is_entropy = !strcmp(hname, "entropy");
	char *rndart = NULL;
	char *value = !is_entropy ? malloc(len * 2 + 1) : rz_str_newf("%.8f", hctx->entropy);
	if (!value) {
		return;
	}
	if (!is_entropy) {
		if (ctx->little_endian) {
			for (int i = 0, bsize; i < len; i++) {
				bsize = (len - i) * 2 + 1;
				snprintf(value + (i * 2), bsize, "%02x", buffer[len - i - 1]);
			}
		} else {
			for (int i = 0, bsize; i < len; i++) {
				bsize = (len - i) * 2 + 1;
				snprintf(value + (i * 2), bsize, "%02x", buffer[i]);
			}
		}
	}

	bool has_seed = !ctx->iv && ctx->seed.len > 0;

	switch (ctx->mode) {
	case RZ_HASH_MODE_JSON:
		if (has_seed) {
			pj_kb(ctx->pj, "seed", true);
		}
		pj_kn(ctx->pj, "from", from);
		pj_kn(ctx->pj, "to", to);
		pj_ks(ctx->pj, "name", hname);
		if (is_entropy) {
			pj_kd(ctx->pj, "entropy", hctx->entropy);
		} else {
			pj_ks(ctx->pj, "hash", value);
		}
		break;
	case RZ_HASH_MODE_STANDARD:
		printf("%s: 0x%08" PFMT64x "-0x%08" PFMT64x " %s: %s%s\n", filename, from, to, hname, value, has_seed ? " with seed" : "");
		break;
	case RZ_HASH_MODE_RANDOMART:
		rndart = rz_print_randomart(buffer, len, from);
		printf("%s\n%s\n", hname, rndart);
		break;
	case RZ_HASH_MODE_QUIET:
		printf("%s: %s: %s\n", filename, hname, value);
		break;
	case RZ_HASH_MODE_VERY_QUIET:
		printf("%s", value);
		break;
	}
	free(value);
	free(rndart);
}

static void rz_hash_context_compare_hashes(RzHashContext *ctx, size_t filesize, bool result, const char *hname, const char *filename) {
	ut64 to = ctx->offset.to ? ctx->offset.to : filesize;
	switch (ctx->mode) {
	case RZ_HASH_MODE_JSON:
		pj_kb(ctx->pj, "seed", ctx->seed.len > 0);
		pj_kb(ctx->pj, "compare", result);
		pj_kn(ctx->pj, "from", ctx->offset.from);
		pj_kn(ctx->pj, "to", to);
		pj_ks(ctx->pj, "name", hname);
		break;
	case RZ_HASH_MODE_RANDOMART:
	case RZ_HASH_MODE_STANDARD:
		printf("%s: 0x%08" PFMT64x "-0x%08" PFMT64x " %s: computed hash %s the expected one\n", filename, ctx->offset.from, to, hname, result ? "matches" : "doesn't match");
		break;
	case RZ_HASH_MODE_QUIET:
		printf("%s: %s: computed hash %s the expected one\n", filename, hname, result ? "matches" : "doesn't match");
		break;
	case RZ_HASH_MODE_VERY_QUIET:
		printf("%s", result ? "true" : "false");
		break;
	}
}

static bool calculate_hash(RzHashContext *ctx, RzIO *io, const char *filename) {
	bool result = false;
	const char *hname = NULL;
	RzHash *hctx = NULL;
	ut64 algorithms, filesize;
	ut8 digest[128] = { 0 };
	ut64 bsize = 0;
	ut8 *block = NULL;
	ut8 *cmphash = NULL;

	algorithms = rz_hash_name_to_bits(ctx->algorithm);
	if (algorithms < 1) {
		RZ_LOG_ERROR("rz-hash: error, invalid hash algorithm\n");
		goto calculate_hash_end;
	}

	filesize = rz_io_desc_size(io->desc);

	hctx = rz_hash_new(true, algorithms);
	if (!hctx) {
		RZ_LOG_ERROR("rz-hash: error, cannot allocate hash context memory\n");
		goto calculate_hash_end;
	}

	if (ctx->offset.to > filesize) {
		RZ_LOG_ERROR("rz-hash: error, -t value is greater than file size\n");
		goto calculate_hash_end;
	}

	if (ctx->offset.from > filesize) {
		RZ_LOG_ERROR("rz-hash: error, -f value is greater than file size\n");
		goto calculate_hash_end;
	}

	bsize = ctx->block_size;
	block = malloc(bsize);
	if (!block) {
		RZ_LOG_ERROR("rz-hash: error, cannot allocate block memory\n");
		goto calculate_hash_end;
	}

	if (ctx->compare) {
		ut64 to = ctx->offset.to ? ctx->offset.to : filesize;
		size_t cmphashlen = 0;
		bool result = false;

		if (!rz_hash_parse_hexadecimal("-c", ctx->compare, &cmphash, &cmphashlen)) {
			//RZ_LOG_ERROR("rz-hash: error, cannot allocate block memory\n");
			goto calculate_hash_end;
		}

		for (ut64 i = 1; i < RZ_HASH_ALL; i <<= 1) {
			if (!(algorithms & i)) {
				continue;
			}
			hname = rz_hash_name(i);
			if (IS_NULLSTR(hname)) {
				// not all bits are used.
				continue;
			}
			int hashlen = rz_hash_size(i);
			if (hashlen != cmphashlen) {
				result = false;
			} else {
				rz_hash_do_begin(hctx, i);
				if (ctx->seed.as_prefix && ctx->seed.buf) {
					rz_hash_do_update(hctx, i, ctx->seed.buf, ctx->seed.len);
				}

				for (ut64 j = ctx->offset.from; j < to; j += bsize) {
					int read = rz_io_pread_at(io, j, block, to - j > bsize ? bsize : (to - j));
					rz_hash_do_update(hctx, i, block, read);
				}

				if (!ctx->seed.as_prefix && ctx->seed.buf) {
					rz_hash_do_update(hctx, i, ctx->seed.buf, ctx->seed.len);
				}

				rz_hash_do_end(hctx, i);
				memcpy(digest, hctx->digest, hashlen);

				for (ut64 k = 0; k < ctx->iterate; ++k) {
					rz_hash_calculate(hctx, i, digest, hashlen);
					memcpy(digest, hctx->digest, hashlen);
				}

				result = !memcmp(cmphash, digest, hashlen);
			}

			if (ctx->mode == RZ_HASH_MODE_JSON) {
				pj_o(ctx->pj);
			} else if (ctx->mode == RZ_HASH_MODE_VERY_QUIET && ctx->newline) {
				printf("\n");
				fflush(stdout);
			}
			rz_hash_context_compare_hashes(ctx, filesize, result, hname, filename);
			if (ctx->mode == RZ_HASH_MODE_JSON) {
				pj_end(ctx->pj);
			}
			ctx->newline = true;
		}
	} else if (ctx->show_blocks) {
		ut64 to = ctx->offset.to ? ctx->offset.to : filesize;
		for (ut64 i = 1; i < RZ_HASH_ALL; i <<= 1) {
			if (!(algorithms & i)) {
				continue;
			}

			int hashlen = rz_hash_size(i);
			hname = rz_hash_name(i);
			for (ut64 j = ctx->offset.from; j < to; j += bsize) {
				int read = rz_io_pread_at(io, j, block, to - j > bsize ? bsize : (to - j));

				rz_hash_calculate(hctx, i, block, read);
				memcpy(digest, hctx->digest, hashlen);

				for (ut64 k = 0; k < ctx->iterate; ++k) {
					rz_hash_calculate(hctx, i, digest, hashlen);
					memcpy(digest, hctx->digest, hashlen);
				}

				if (ctx->mode == RZ_HASH_MODE_JSON) {
					pj_o(ctx->pj);
				} else if (ctx->mode == RZ_HASH_MODE_VERY_QUIET && ctx->newline) {
					printf("\n");
					fflush(stdout);
				}
				rz_hash_print_digest(ctx, hctx, hname, digest, hashlen, j, j + bsize, filename);
				if (ctx->mode == RZ_HASH_MODE_JSON) {
					pj_end(ctx->pj);
				}
				ctx->newline = true;
			}
		}
	} else {
		ut64 to = ctx->offset.to ? ctx->offset.to : filesize;
		for (ut64 i = 1; i < RZ_HASH_ALL; i <<= 1) {
			if (!(algorithms & i)) {
				continue;
			}

			hname = rz_hash_name(i);
			int hashlen = rz_hash_size(i);

			rz_hash_do_begin(hctx, i);
			if (ctx->seed.as_prefix && ctx->seed.buf) {
				rz_hash_do_update(hctx, i, ctx->seed.buf, ctx->seed.len);
			}

			for (ut64 j = ctx->offset.from; j < to; j += bsize) {
				int read = rz_io_pread_at(io, j, block, to - j > bsize ? bsize : (to - j));
				rz_hash_do_update(hctx, i, block, read);
			}

			if (!ctx->seed.as_prefix && ctx->seed.buf) {
				rz_hash_do_update(hctx, i, ctx->seed.buf, ctx->seed.len);
			}

			rz_hash_do_end(hctx, i);
			memcpy(digest, hctx->digest, hashlen);

			for (ut64 k = 0; k < ctx->iterate; ++k) {
				rz_hash_calculate(hctx, i, digest, hashlen);
				memcpy(digest, hctx->digest, hashlen);
			}

			if (ctx->mode == RZ_HASH_MODE_JSON) {
				pj_o(ctx->pj);
			} else if (ctx->mode == RZ_HASH_MODE_VERY_QUIET && ctx->newline) {
				printf("\n");
				fflush(stdout);
			}
			rz_hash_print_digest(ctx, hctx, hname, digest, hashlen, ctx->offset.from, to, filename);
			if (ctx->mode == RZ_HASH_MODE_JSON) {
				pj_end(ctx->pj);
			}
			ctx->newline = true;
		}
	}
	result = true;

calculate_hash_end:
	free(block);
	free(cmphash);
	rz_hash_free(hctx);
	return result;
}

static bool calculate_decrypt(RzHashContext *ctx, RzIO *io, const char *filename) {
	RzCrypto *cry = NULL;
	bool result = false;
	ut8 *iv = NULL;
	size_t ivlen = 0;
	ut64 filesize = 0;
	ut64 bsize = 0;
	ut8 *block = NULL;

	if (ctx->iv) {
		if (!strncmp(ctx->iv, "s:", 2)) {
			if (!rz_hash_parse_string("-I", ctx->iv + 2, &iv, &ivlen)) {
				goto calculate_decrypt_end;
			}
		} else {
			if (!rz_hash_parse_hexadecimal("-I", ctx->iv, &iv, &ivlen)) {
				goto calculate_decrypt_end;
			}
		}
	}

	cry = rz_crypto_new();
	if (!cry) {
		RZ_LOG_ERROR("rz-hash: error, failed to allocate memory\n");
		goto calculate_decrypt_end;
	}

	if (!rz_crypto_use(cry, ctx->algorithm)) {
		RZ_LOG_ERROR("rz-hash: error, unknown encryption algorithm '%s'\n", ctx->algorithm);
		goto calculate_decrypt_end;
	}

	if (!rz_crypto_set_key(cry, ctx->seed.buf, ctx->seed.len, 0, RZ_CRYPTO_DIR_DECRYPT)) {
		RZ_LOG_ERROR("rz-hash: error, invalid key\n");
		goto calculate_decrypt_end;
	}

	if (iv && !rz_crypto_set_iv(cry, iv, ivlen)) {
		RZ_LOG_ERROR("rz-hash: error, invalid IV.\n");
		goto calculate_decrypt_end;
	}

	filesize = rz_io_desc_size(io->desc);
	if (filesize < 1) {
		RZ_LOG_ERROR("rz-hash: error, file size is less than 1\n");
		goto calculate_decrypt_end;
	}

	bsize = ctx->block_size;
	block = malloc(bsize);
	if (!block) {
		RZ_LOG_ERROR("rz-hash: error, cannot allocate block memory\n");
		goto calculate_decrypt_end;
	}

	ut64 to = ctx->offset.to ? ctx->offset.to : filesize;
	for (ut64 j = ctx->offset.from; j < to; j += bsize) {
		int read = rz_io_pread_at(io, j, block, to - j > bsize ? bsize : (to - j));
		rz_crypto_update(cry, block, read);
	}

	rz_crypto_final(cry, NULL, 0);

	int plaintext_size = 0;
	const ut8 *plaintext = rz_crypto_get_output(cry, &plaintext_size);

	rz_hash_print_crypto(ctx, ctx->algorithm, plaintext, plaintext_size, ctx->offset.from, to);
	result = true;

calculate_decrypt_end:
	free(block);
	free(iv);
	rz_crypto_free(cry);
	return result;
}

static bool calculate_encrypt(RzHashContext *ctx, RzIO *io, const char *filename) {
	RzCrypto *cry = NULL;
	bool result = false;
	ut8 *iv = NULL;
	size_t ivlen = 0;
	ut64 filesize = 0;
	ut64 bsize = 0;
	ut8 *block = NULL;

	bool requires_key = !strncmp("base", ctx->algorithm, 4) || !strcmp("punycode", ctx->algorithm);
	if (!requires_key && ctx->seed.len < 1) {
		RZ_LOG_ERROR("rz-hash: error, cannot encrypt without a key\n");
		goto calculate_encrypt_end;
	}

	if (ctx->iv) {
		if (!strncmp(ctx->iv, "s:", 2)) {
			if (!rz_hash_parse_string("-I", ctx->iv + 2, &iv, &ivlen)) {
				goto calculate_encrypt_end;
			}
		} else {
			if (!rz_hash_parse_hexadecimal("-I", ctx->iv, &iv, &ivlen)) {
				goto calculate_encrypt_end;
			}
		}
	}

	cry = rz_crypto_new();
	if (!cry) {
		RZ_LOG_ERROR("rz-hash: error, failed to allocate memory\n");
		goto calculate_encrypt_end;
	}

	if (!rz_crypto_use(cry, ctx->algorithm)) {
		RZ_LOG_ERROR("rz-hash: error, unknown encryption algorithm '%s'\n", ctx->algorithm);
		goto calculate_encrypt_end;
	}

	if (!rz_crypto_set_key(cry, ctx->seed.buf, ctx->seed.len, 0, RZ_CRYPTO_DIR_ENCRYPT)) {
		RZ_LOG_ERROR("rz-hash: error, invalid key\n");
		goto calculate_encrypt_end;
	}

	if (iv && !rz_crypto_set_iv(cry, iv, ivlen)) {
		RZ_LOG_ERROR("rz-hash: error, invalid IV.\n");
		goto calculate_encrypt_end;
	}

	filesize = rz_io_desc_size(io->desc);
	if (filesize < 1) {
		RZ_LOG_ERROR("rz-hash: error, file size is less than 1\n");
		goto calculate_encrypt_end;
	}

	bsize = ctx->block_size;
	block = malloc(bsize);
	if (!block) {
		RZ_LOG_ERROR("rz-hash: error, cannot allocate block memory\n");
		goto calculate_encrypt_end;
	}

	ut64 to = ctx->offset.to ? ctx->offset.to : filesize;
	for (ut64 j = ctx->offset.from; j < to; j += bsize) {
		int read = rz_io_pread_at(io, j, block, to - j > bsize ? bsize : (to - j));
		rz_crypto_update(cry, block, read);
	}

	rz_crypto_final(cry, NULL, 0);

	int ciphertext_size = 0;
	const ut8 *ciphertext = rz_crypto_get_output(cry, &ciphertext_size);

	rz_hash_print_crypto(ctx, ctx->algorithm, ciphertext, ciphertext_size, ctx->offset.from, to);
	result = true;

calculate_encrypt_end:
	free(block);
	free(iv);
	rz_crypto_free(cry);
	return result;
}

RZ_API int rz_main_rz_hash(int argc, const char **argv) {
	int result = 1;
	RzHashContext ctx;

	rz_hash_parse_cmdline(argc, argv, &ctx);

	switch (ctx.operation) {
	case RZ_HASH_OP_LIST_ALGO:
		rz_hash_show_algorithms();
		break;
	case RZ_HASH_OP_HASH:
		if (!rz_hash_context_run(&ctx, calculate_hash)) {
			goto rz_main_rz_hash_end;
		}
		break;
	case RZ_HASH_OP_DECRYPT:
		if (!rz_hash_context_run(&ctx, calculate_decrypt)) {
			goto rz_main_rz_hash_end;
		}
		break;
	case RZ_HASH_OP_ENCRYPT:
		if (!rz_hash_context_run(&ctx, calculate_encrypt)) {
			goto rz_main_rz_hash_end;
		}
		break;
	case RZ_HASH_OP_VERSION:
		rz_main_version_print("rz-hash");
		break;
	case RZ_HASH_OP_USAGE:
		rz_hash_show_help(true);
		goto rz_main_rz_hash_end;
	case RZ_HASH_OP_ERROR:
		goto rz_main_rz_hash_end;
	case RZ_HASH_OP_HELP:
		result = 0;
	default:
		rz_hash_show_help(false);
		goto rz_main_rz_hash_end;
	}

	result = 0;

rz_main_rz_hash_end:
	rz_hash_context_fini(&ctx);
	return result;
}
