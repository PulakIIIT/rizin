// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_analysis.h>

#include "../../asm/arch/java/jvm.h"

static int java_analysis(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	JavaVM vm = { 0 };
	Bytecode bc = { 0 };

	if (!jvm_init(&vm, buf, len, addr)) {
		eprintf("[!] java_analysis: bad or invalid data.\n");
		return -1;
	}

	op->fail = UT64_MAX;
	op->jump = UT64_MAX;
	op->size = 1;
	if (jvm_fetch(&vm, &bc)) {
		op->type = bc.atype;
		switch (bc.atype) {
		case RZ_ANALYSIS_OP_TYPE_CALL:
		case RZ_ANALYSIS_OP_TYPE_JMP:
			op->jump = bc.pc + bc.args[0];
			break;
		case RZ_ANALYSIS_OP_TYPE_CJMP:
			op->jump = bc.pc + bc.args[0];
			op->fail = addr + bc.size;
			break;
		case RZ_ANALYSIS_OP_TYPE_RET:
		case RZ_ANALYSIS_OP_TYPE_ILL:
			op->eob = true;
			break;
		default:
			break;
		}
		bytecode_clean(&bc);
	} else {
		eprintf("[!] java_analysis: jvm fetch failed.\n");
		return -1;
	}
	return op->size;
}

static bool set_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	pc\n"
		"=SP	garbage\n"
		"=SR	garbage\n"
		"=A0	garbage\n"
		"=A1	garbage\n"
		"=A2	garbage\n"
		"=A3	garbage\n"
		"=A4	garbage\n"
		"=A5	garbage\n"
		"=A6	garbage\n"
		"gpr	pc	    .32 0  0\n"
		"gpr	garbage	.32 32 0\n";
	return rz_reg_set_profile_string(analysis->reg, p);
}

static int archinfo(RzAnalysis *analysis, int query) {
	if (query == RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE) {
		return 1;
	} else if (query == RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE) {
		return 5;
	}
	return 0;
}

RzAnalysisPlugin rz_analysis_plugin_java = {
	.name = "java",
	.desc = "Java analysis plugin",
	.arch = "java",
	.license = "LGPL3",
	.bits = 32,
	.op = &java_analysis,
	.archinfo = archinfo,
	.set_reg_profile = &set_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_java,
	.version = RZ_VERSION
};
#endif
