// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_core.h>

#include "../arch/java/jvm.h"

static int java_disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	JavaVM vm = { 0 };
	Bytecode bc = { 0 };

	rz_strbuf_set(&op->buf_asm, "invalid");

	if (!jvm_init(&vm, buf, len, a->pc)) {
		eprintf("[!] java_disassemble: bad or invalid data.\n");
		return -1;
	}
	op->size = 1;
	if (jvm_fetch(&vm, &bc)) {
		op->size = bc.size;
		bytecode_snprint(&op->buf_asm, &bc);
		bytecode_clean(&bc);
	} else {
		eprintf("[!] java_disassemble: jvm fetch failed.\n");
		return -1;
	}
	return op->size;
}

RzAsmPlugin rz_asm_plugin_java = {
	.name = "java",
	.desc = "Java bytecode disassembler",
	.arch = "java",
	.license = "LGPL-3",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
	.disassemble = &java_disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_java,
	.version = RZ_VERSION
};
#endif
