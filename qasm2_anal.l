/*
 * Copyright (c) 2016 Sugizaki Yukimasa
 * All rights reserved.
 *
 * This software is licensed under a Modified (3-Clause) BSD License.
 * You should have received a copy of this license along with this
 * software. If not, contact the copyright holder above.
 */

%{
#include "qasm2.h"
#include "qasm2_anal.h"
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <setjmp.h>
#include "rpn_calc.h"
#include "diskstorage.h"
#include "error_fl.h"

typedef enum {
	INST_ALU,
	INST_BRA,
	INST_LI,
	INST_SEM
} inst_inst_t;

typedef enum {
	INST_SIG_SB = 0,
	INST_SIG_NS = 1,
	INST_SIG_TS = 2,
	INST_SIG_PE = 3,
	INST_SIG_WS = 4,
	INST_SIG_SU = 5,
	INST_SIG_LTS = 6,
	INST_SIG_LDCOV = 7,
	INST_SIG_LDCOL = 8,
	INST_SIG_LDCOL_PE = 9,
	INST_SIG_LDTMU0 = 10,
	INST_SIG_LDTMU1 = 11,
	INST_SIG_AL = 12,
	INST_SIG_SIMM = 13
} inst_sig_t;

typedef enum {
	INST_ESIG_32 = 0,
	INST_ESIG_PES = 1,
	INST_ESIG_PEU = 3
} inst_esig_t;

typedef enum {
	INST_UNPACK_3232 = 0,
	INST_UNPACK_16A32 = 1,
	INST_UNPACK_16B32 = 2,
	INST_UNPACK_8D8888 = 3,
	INST_UNPACK_8A32 = 4,
	INST_UNPACK_8B32 = 5,
	INST_UNPACK_8C32 = 6,
	INST_UNPACK_8D32 = 7
} inst_unpack_t;

typedef enum {
	INST_PM_0 = 0,
	INST_PM_1 = 1
} inst_pm_t;

typedef enum {
	INST_PACK_3232 = 0,
	INST_PACK_3216A = 1,
	INST_PACK_3216B = 2,
	INST_PACK_328888 = 3,
	INST_PACK_328A = 4,
	INST_PACK_328B = 5,
	INST_PACK_328C = 6,
	INST_PACK_328D = 7,
	INST_PACK_3232S = 8,
	INST_PACK_3216AS = 9,
	INST_PACK_3216BS = 10,
	INST_PACK_328888S = 11,
	INST_PACK_328AS = 12,
	INST_PACK_328BS = 13,
	INST_PACK_328CS = 14,
	INST_PACK_328CD = 15
} inst_pack_t;

typedef enum {
	INST_COND_ADDMUL_NV = 0,
	INST_COND_ADDMUL_AL = 1,
	INST_COND_ADDMUL_ZS = 2,
	INST_COND_ADDMUL_ZC = 3,
	INST_COND_ADDMUL_NS = 4,
	INST_COND_ADDMUL_NC = 5,
	INST_COND_ADDMUL_CS = 6,
	INST_COND_ADDMUL_CC = 7
}	inst_cond_addmul_t;

typedef enum {
	INST_SF_0 = 0,
	INST_SF_1 = 1
} inst_sf_t;

typedef enum {
	INST_WS_0 = 0,
	INST_WS_1 = 1
} inst_ws_t;

typedef enum {
	INST_RWADDR_ADDMULAB_RA0 = 0,
	INST_RWADDR_ADDMULAB_RB0 = 0,

	INST_RWADDR_ADDMULAB_RA1 = 1,
	INST_RWADDR_ADDMULAB_RB1 = 1,

	INST_RWADDR_ADDMULAB_RA2 = 2,
	INST_RWADDR_ADDMULAB_RB2 = 2,

	INST_RWADDR_ADDMULAB_RA3 = 3,
	INST_RWADDR_ADDMULAB_RB3 = 3,

	INST_RWADDR_ADDMULAB_RA4 = 4,
	INST_RWADDR_ADDMULAB_RB4 = 4,

	INST_RWADDR_ADDMULAB_RA5 = 5,
	INST_RWADDR_ADDMULAB_RB5 = 5,

	INST_RWADDR_ADDMULAB_RA6 = 6,
	INST_RWADDR_ADDMULAB_RB6 = 6,

	INST_RWADDR_ADDMULAB_RA7 = 7,
	INST_RWADDR_ADDMULAB_RB7 = 7,

	INST_RWADDR_ADDMULAB_RA8 = 8,
	INST_RWADDR_ADDMULAB_RB8 = 8,

	INST_RWADDR_ADDMULAB_RA9 = 9,
	INST_RWADDR_ADDMULAB_RB9 = 9,

	INST_RWADDR_ADDMULAB_RA10 = 10,
	INST_RWADDR_ADDMULAB_RB10 = 10,

	INST_RWADDR_ADDMULAB_RA11 = 11,
	INST_RWADDR_ADDMULAB_RB11 = 11,

	INST_RWADDR_ADDMULAB_RA12 = 12,
	INST_RWADDR_ADDMULAB_RB12 = 12,

	INST_RWADDR_ADDMULAB_RA13 = 13,
	INST_RWADDR_ADDMULAB_RB13 = 13,

	INST_RWADDR_ADDMULAB_RA14 = 14,
	INST_RWADDR_ADDMULAB_RB14 = 14,

	INST_RWADDR_ADDMULAB_RA15 = 15,
	INST_RWADDR_ADDMULAB_RB15 = 15,

	INST_RWADDR_ADDMULAB_RA16 = 16,
	INST_RWADDR_ADDMULAB_RB16 = 16,

	INST_RWADDR_ADDMULAB_RA17 = 17,
	INST_RWADDR_ADDMULAB_RB17 = 17,

	INST_RWADDR_ADDMULAB_RA18 = 18,
	INST_RWADDR_ADDMULAB_RB18 = 18,

	INST_RWADDR_ADDMULAB_RA19 = 19,
	INST_RWADDR_ADDMULAB_RB19 = 19,

	INST_RWADDR_ADDMULAB_RA20 = 20,
	INST_RWADDR_ADDMULAB_RB20 = 20,

	INST_RWADDR_ADDMULAB_RA21 = 21,
	INST_RWADDR_ADDMULAB_RB21 = 21,

	INST_RWADDR_ADDMULAB_RA22 = 22,
	INST_RWADDR_ADDMULAB_RB22 = 22,

	INST_RWADDR_ADDMULAB_RA23 = 23,
	INST_RWADDR_ADDMULAB_RB23 = 23,

	INST_RWADDR_ADDMULAB_RA24 = 24,
	INST_RWADDR_ADDMULAB_RB24 = 24,

	INST_RWADDR_ADDMULAB_RA25 = 25,
	INST_RWADDR_ADDMULAB_RB25 = 25,

	INST_RWADDR_ADDMULAB_RA26 = 26,
	INST_RWADDR_ADDMULAB_RB26 = 26,

	INST_RWADDR_ADDMULAB_RA27 = 27,
	INST_RWADDR_ADDMULAB_RB27 = 27,

	INST_RWADDR_ADDMULAB_RA28 = 28,
	INST_RWADDR_ADDMULAB_RB28 = 28,

	INST_RWADDR_ADDMULAB_RA29 = 29,
	INST_RWADDR_ADDMULAB_RB29 = 29,

	INST_RWADDR_ADDMULAB_RA30 = 30,
	INST_RWADDR_ADDMULAB_RB30 = 30,

	INST_RWADDR_ADDMULAB_RA31 = 31,
	INST_RWADDR_ADDMULAB_RB31 = 31,

	INST_RWADDR_ADDMULAB_UNIFORM_READ = 32,
	INST_RWADDR_ADDMULAB_R0 = 32,

	INST_RWADDR_ADDMULAB_R1 = 33,

	INST_RWADDR_ADDMULAB_R2 = 34,

	INST_RWADDR_ADDMULAB_R3 = 35,

	INST_RWADDR_ADDMULAB_TMU_NOSWAP = 36,

	INST_RWADDR_ADDMULAB_R5 = 37,

	INST_RWADDR_ADDMULAB_ELEMENT_NUMBER = 38,
	INST_RWADDR_ADDMULAB_QPU_NUMBER = 38,
	INST_RWADDR_ADDMULAB_HOST_INT = 38,

	INST_RWADDR_ADDMULAB_NOP = 39,

	INST_RWADDR_ADDMULAB_UNIFORMS_ADDRESS = 40,

	INST_RWADDR_ADDMULAB_VPM_READ = 48,
	INST_RWADDR_ADDMULAB_VPM_WRITE = 48,

	INST_RWADDR_ADDMULAB_VPM_LD_BUSY = 49,
	INST_RWADDR_ADDMULAB_VPM_ST_BUSY = 49,
	INST_RWADDR_ADDMULAB_VPMVCD_WR_SETUP = 49,
	INST_RWADDR_ADDMULAB_VPMVCD_RD_SETUP = 49,

	INST_RWADDR_ADDMULAB_VPM_LD_WAIT = 50,
	INST_RWADDR_ADDMULAB_VPM_ST_WAIT = 50,
	INST_RWADDR_ADDMULAB_VPM_LD_ADDR = 50,
	INST_RWADDR_ADDMULAB_VPM_ST_ADDR = 50,

	INST_RWADDR_ADDMULAB_MUTEX_ACQUIRE = 51,
	INST_RWADDR_ADDMULAB_MUTEX_RELEASE = 51,

	INST_RWADDR_ADDMULAB_SFU_RECIP = 52,

	INST_RWADDR_ADDMULAB_SFU_RECIPSQRT = 53,

	INST_RWADDR_ADDMULAB_SFU_EXP = 54,

	INST_RWADDR_ADDMULAB_SFU_LOG = 55,

	INST_RWADDR_ADDMULAB_TMU0S = 56,

	INST_RWADDR_ADDMULAB_TMU0T = 57,

	INST_RWADDR_ADDMULAB_TMU0R = 58,

	INST_RWADDR_ADDMULAB_TMU0B = 59,

	INST_RWADDR_ADDMULAB_TMU1S = 60,

	INST_RWADDR_ADDMULAB_TMU1T = 61,

	INST_RWADDR_ADDMULAB_TMU1R = 62,

	INST_RWADDR_ADDMULAB_TMU1B = 63
} inst_rwaddr_addmulab_t;

typedef enum {
	INST_SIMM_0 = 0,
	INST_SIMM_1 = 1,
	INST_SIMM_2 = 2,
	INST_SIMM_3 = 3,
	INST_SIMM_4 = 4,
	INST_SIMM_5 = 5,
	INST_SIMM_6 = 6,
	INST_SIMM_7 = 7,
	INST_SIMM_8 = 8,
	INST_SIMM_9 = 9,
	INST_SIMM_10 = 10,
	INST_SIMM_11 = 11,
	INST_SIMM_12 = 12,
	INST_SIMM_13 = 13,
	INST_SIMM_14 = 14,
	INST_SIMM_15 = 15,
	INST_SIMM_M16 = 16,
	INST_SIMM_M15 = 17,
	INST_SIMM_M14 = 18,
	INST_SIMM_M13 = 19,
	INST_SIMM_M12 = 20,
	INST_SIMM_M11 = 21,
	INST_SIMM_M10 = 22,
	INST_SIMM_M9 = 23,
	INST_SIMM_M8 = 24,
	INST_SIMM_M7 = 25,
	INST_SIMM_M6 = 26,
	INST_SIMM_M5 = 27,
	INST_SIMM_M4 = 28,
	INST_SIMM_M3 = 29,
	INST_SIMM_M2 = 30,
	INST_SIMM_M1 = 31,
	INST_SIMM_1F = 32,
	INST_SIMM_2F = 33,
	INST_SIMM_4F = 34,
	INST_SIMM_8F = 35,
	INST_SIMM_16F = 36,
	INST_SIMM_32F = 37,
	INST_SIMM_64F = 38,
	INST_SIMM_128F = 39,
	INST_SIMM_1_256F = 40,
	INST_SIMM_1_128F = 41,
	INST_SIMM_1_64F = 42,
	INST_SIMM_1_32F = 43,
	INST_SIMM_1_16F = 44,
	INST_SIMM_1_8F = 45,
	INST_SIMM_1_4F = 46,
	INST_SIMM_1_2F = 47,
	INST_SIMM_VRR5 = 48,
	INST_SIMM_VR1 = 49,
	INST_SIMM_VR2 = 50,
	INST_SIMM_VR3 = 51,
	INST_SIMM_VR4 = 52,
	INST_SIMM_VR5 = 53,
	INST_SIMM_VR6 = 54,
	INST_SIMM_VR7 = 55,
	INST_SIMM_VR8 = 56,
	INST_SIMM_VR9 = 57,
	INST_SIMM_VR10 = 58,
	INST_SIMM_VR11 = 59,
	INST_SIMM_VR12 = 60,
	INST_SIMM_VR13 = 61,
	INST_SIMM_VR14 = 62,
	INST_SIMM_VR15 = 63
} inst_simm_t;

typedef enum {
	INST_OP_MUL_NOP = 0,
	INST_OP_MUL_FMUL = 1,
	INST_OP_MUL_MUL24 = 2,
	INST_OP_MUL_V8MULD = 3,
	INST_OP_MUL_V8MIN = 4,
	INST_OP_MUL_V8MAX = 5,
	INST_OP_MUL_V8ADDS = 6,
	INST_OP_MUL_V8SUBS = 7
} inst_op_mul_t;

typedef enum {
	INST_OP_ADD_NOP = 0,
	INST_OP_ADD_FADD = 1,
	INST_OP_ADD_FSUB = 2,
	INST_OP_ADD_FMIN = 3,
	INST_OP_ADD_FMAX = 4,
	INST_OP_ADD_FMINABS = 5,
	INST_OP_ADD_FMAXABS = 6,
	INST_OP_ADD_FTOI = 7,
	INST_OP_ADD_ITOF = 8,
	INST_OP_ADD_ADD = 12,
	INST_OP_ADD_SUB = 13,
	INST_OP_ADD_SHR = 14,
	INST_OP_ADD_ASR = 15,
	INST_OP_ADD_ROR = 16,
	INST_OP_ADD_SHL = 17,
	INST_OP_ADD_MIN = 18,
	INST_OP_ADD_MAX = 19,
	INST_OP_ADD_AND = 20,
	INST_OP_ADD_OR = 21,
	INST_OP_ADD_XOR = 22,
	INST_OP_ADD_NOT = 23,
	INST_OP_ADD_CLZ = 24,
	INST_OP_ADD_V8ADDS = 30,
	INST_OP_ADD_V8SUBS = 31
} inst_op_add_t;

typedef enum {
	INST_ADDMUL_AB_R0 = 0,
	INST_ADDMUL_AB_R1 = 1,
	INST_ADDMUL_AB_R2 = 2,
	INST_ADDMUL_AB_R3 = 3,
	INST_ADDMUL_AB_R4 = 4,
	INST_ADDMUL_AB_R5 = 5,
	INST_ADDMUL_AB_RA = 6,
	INST_ADDMUL_AB_RB = 7
} inst_addmul_ab_t;

typedef enum {
	INST_COND_BR_ALLZS = 0,
	INST_COND_BR_ALLZC = 1,
	INST_COND_BR_ANYZS = 2,
	INST_COND_BR_ANYZC = 3,
	INST_COND_BR_ALLNS = 4,
	INST_COND_BR_ALLNC = 5,
	INST_COND_BR_ANYNS = 6,
	INST_COND_BR_ANYNC = 7,
	INST_COND_BR_ALLCS = 8,
	INST_COND_BR_ALLCC = 9,
	INST_COND_BR_ANYCS = 10,
	INST_COND_BR_ANYCC = 11,
	INST_COND_BR_AL = 15
} inst_cond_br_t;

typedef enum {
	INST_REL_0,
	INST_REL_1
} inst_rel_t;

typedef enum {
	INST_REG_0,
	INST_REG_1
} inst_reg_t;

typedef int32_t inst_imm_t;

typedef enum {
	INST_SA_INC = 0,
	INST_SA_DEC = 1
} inst_sa_t;

typedef enum {
	INST_SEM_0 = 0,
	INST_SEM_1 = 1,
	INST_SEM_2 = 2,
	INST_SEM_3 = 3,
	INST_SEM_4 = 4,
	INST_SEM_5 = 5,
	INST_SEM_6 = 6,
	INST_SEM_7 = 7,
	INST_SEM_8 = 8,
	INST_SEM_9 = 9,
	INST_SEM_10 = 10,
	INST_SEM_11 = 11,
	INST_SEM_12 = 12,
	INST_SEM_13 = 13,
	INST_SEM_14 = 14,
	INST_SEM_15 = 15
} inst_sem_t;

typedef enum {
	MIDIMM_TYPE_INT,
	MIDIMM_TYPE_FLOAT
} midimm_type_t;

typedef struct {
	midimm_type_t type;
	int32_t ival;
	float fval;
} midimm_t;

typedef struct {
	struct {
		_Bool inst;
		_Bool sig;
		_Bool esig;
		_Bool unpack;
		_Bool pm;
		_Bool pack;
		_Bool cond_add, cond_mul;
		_Bool sf;
		_Bool ws;
		_Bool waddr_add, waddr_mul, raddr_a, raddr_b;
		_Bool simm;
		_Bool op_mul, op_add;
		_Bool cond_br, rel, reg;
		_Bool add_a, add_b, mul_a, mul_b;
		_Bool imm;
		_Bool sa, sem;
	} is_set;
	struct {
		_Bool simm, imm;
	} is_saved;
	inst_inst_t inst;
	inst_sig_t sig;
	inst_esig_t esig;
	inst_unpack_t unpack;
	inst_pm_t pm;
	inst_pack_t pack;
	inst_cond_addmul_t cond_add, cond_mul;
	inst_sf_t sf;
	inst_ws_t ws;
	inst_rwaddr_addmulab_t waddr_add, waddr_mul, raddr_a, raddr_b;
	inst_simm_t simm;
	inst_op_mul_t op_mul;
	inst_op_add_t op_add;
	inst_addmul_ab_t add_a, add_b, mul_a, mul_b;
	inst_cond_br_t cond_br;
	inst_rel_t rel;
	inst_reg_t reg;
	inst_imm_t imm;
	inst_sa_t sa;
	inst_sem_t sem;
} inst_t;

typedef enum {
	ID_COND_ADDMUL_COND_ADD,
	ID_COND_ADDMUL_COND_MUL
} id_cond_addmul_t;

typedef enum {
	ID_RWADDR_ADDMULAB_WADDR_ADD,
	ID_RWADDR_ADDMULAB_WADDR_MUL,
	ID_RWADDR_ADDMULAB_RADDR_A,
	ID_RWADDR_ADDMULAB_RADDR_B
} id_rwaddr_addmulab_t;

typedef enum {
	ID_ADDMUL_AB_ADD_A,
	ID_ADDMUL_AB_ADD_B,
	ID_ADDMUL_AB_MUL_A,
	ID_ADDMUL_AB_MUL_B
} id_addmul_ab_t;

static int line_number, program_number;
static inst_t inst;
static diskstorage_t ds_inst, ds_simm_imm_str, ds_label, ds_label_program_number;
static jmp_buf jenv;

static void assemble_init();
static void assemble_finalize();
static void end_of_line(const _Bool is_comment_only_line);
static void inst_init(inst_inst_t inst);
static void inst_reset();
static void alu_sig(inst_sig_t sig);
static void alu_unpack(inst_unpack_t inst_unpack);
static void alu_pm(inst_pm_t inst_pm);
static void alu_pack(inst_pack_t inst_pack);
static void alu_cond_addmul(id_cond_addmul_t id_cond_addmul_ab, inst_cond_addmul_t inst_cond_addmul);
static void alu_sf(inst_sf_t inst_sf);
static void alu_ws(inst_ws_t inst_ws);
static void alu_rwaddr_addmulab(id_rwaddr_addmulab_t id_rwaddr_addmul, inst_rwaddr_addmulab_t inst_rwaddr_addmul);
static void alu_simm(inst_simm_t inst_simm);
static void alu_op_mul(inst_op_mul_t inst_op_mul);
static void alu_op_add(inst_op_add_t inst_op_add);
static void alu_addmul_ab(id_addmul_ab_t id_addmul_ab, inst_addmul_ab_t inst_addmul_ab);
static void bra_cond_br(inst_cond_br_t inst_cond_br);
static void bra_rel(inst_rel_t inst_rel);
static void bra_reg(inst_reg_t inst_reg);
static void li_esig(inst_esig_t inst_esig);
static void li_imm(inst_imm_t inst_imm);
static void sem_sa(inst_sa_t inst_sa);
static void sem_sem(inst_sem_t inst_sem);

static id_cond_addmul_t str_to_id_cond_addmul(const char *str);
static id_rwaddr_addmulab_t str_to_id_rwaddr_addmulab(const char *str);
static id_addmul_ab_t str_to_id_addmul_ab(const char *str);

static void valid_inst_inst(const int line, const int n, ...);

static inst_simm_t midimm_to_simm(midimm_t midimm);
static inst_imm_t midimm_to_imm(midimm_t midimm);
static midimm_t rpn_to_midimm(const char *rpn_arg, const _Bool to_remove_surrounding_chars);
static void bra_label_save(const char *str);
static void alu_simm_rpn_save(const char *str);
static void li_imm_rpn_save(const char *str);
static void alu_simm_save_or_expand(const char *str);
static void li_imm_save_or_expand(const char *str);
static char* remove_surrounding_chars(const char *str);
static char* remove_trailing_spaces_and_newlines(const char *str);
static void alu_simm_rpn_save(const char *str);

static void print_inst();
static void print_bin(const uint64_t u, unsigned int width, const _Bool to_print_space);

static void error_invalid_character(const char c);
static void error_q(const char *file, const int line, const char *format, ...);
static void abort_assemble(const int line);

#define INST_IS_SET(NAME) { \
	if (!inst.is_set.inst) \
		error_q(__FILE__, __LINE__, "error: This inst is not initialized yet\n"); \
	else if (inst.is_set.NAME) \
		error_q(__FILE__, __LINE__, "error: %s is already set\n", #NAME); \
}

#define INST_SET(NAME) inst.is_set.NAME = !0

#define INST_IS_SAVED(NAME) { \
	if (!inst.is_set.inst) \
		error_q(__FILE__, __LINE__, "error: This inst is not initialized yet\n"); \
	else if (inst.is_saved.NAME) \
		error_q(__FILE__, __LINE__, "error: %s is already saved\n", #NAME); \
}

#define INST_SAVED(NAME) inst.is_saved.NAME = !0

%}

%option noyywrap

%%

simm=`[^`\n\r]+` alu_simm_save_or_expand(yytext + 5);
imm=`[^`\n\r]+` li_imm_save_or_expand(yytext + 4);

[ \t]+ ;

^[ \t]*:[^ \t\n\r]+[ \t]*(\n|\r|\r\n) {
	const char *p = yytext;
	while ((*p == ' ') || (*p == '\t'))
		p++;
	bra_label_save(p + 1);
	end_of_line(1);
}

^[ \t]*alu inst_init(INST_ALU);
^[ \t]*bra inst_init(INST_BRA);
^[ \t]*li  inst_init(INST_LI);
^[ \t]*sem inst_init(INST_SEM);

sig=sb alu_sig(INST_SIG_SB);
sig=ns alu_sig(INST_SIG_NS);
sig=ts alu_sig(INST_SIG_TS);
sig=pe alu_sig(INST_SIG_PE);
sig=ws alu_sig(INST_SIG_WS);
sig=su alu_sig(INST_SIG_SU);
sig=lts alu_sig(INST_SIG_LTS);
sig=ldcov alu_sig(INST_SIG_LDCOV);
sig=ldcol alu_sig(INST_SIG_LDCOL);
sig=ldcol_pe alu_sig(INST_SIG_LDCOL_PE);
sig=ldtmu0 alu_sig(INST_SIG_LDTMU0);
sig=ldtmu1 alu_sig(INST_SIG_LDTMU1);
sig=al alu_sig(INST_SIG_AL);
sig=simm alu_sig(INST_SIG_SIMM);

esig=32 li_esig(INST_ESIG_32);
esig=pes li_esig(INST_ESIG_PES);
esig=peu li_esig(INST_ESIG_PEU);

unpack=3232 alu_unpack(INST_UNPACK_3232);
unpack=16a32 alu_unpack(INST_UNPACK_16A32);
unpack=16b32 alu_unpack(INST_UNPACK_16B32);
unpack=8d8888 alu_unpack(INST_UNPACK_8D8888);
unpack=8a32 alu_unpack(INST_UNPACK_8A32);
unpack=8b32 alu_unpack(INST_UNPACK_8B32);
unpack=8c32 alu_unpack(INST_UNPACK_8C32);
unpack=8d32 alu_unpack(INST_UNPACK_8D32);

pm=0 alu_pm(INST_PM_0);
pm=1 alu_pm(INST_PM_1);

pack=3232 alu_pack(INST_PACK_3232);
pack=3216a alu_pack(INST_PACK_3216A);
pack=3216b alu_pack(INST_PACK_3216B);
pack=328888 alu_pack(INST_PACK_328888);
pack=328a alu_pack(INST_PACK_328A);
pack=328b alu_pack(INST_PACK_328B);
pack=328c alu_pack(INST_PACK_328C);
pack=328d alu_pack(INST_PACK_328D);
pack=3232s alu_pack(INST_PACK_3232S);
pack=3216as alu_pack(INST_PACK_3216AS);
pack=3216bs alu_pack(INST_PACK_3216BS);
pack=328888s alu_pack(INST_PACK_328888S);
pack=328as alu_pack(INST_PACK_328AS);
pack=328bs alu_pack(INST_PACK_328BS);
pack=328cs alu_pack(INST_PACK_328CS);
pack=328cd alu_pack(INST_PACK_328CD);

cond_(add|mul)=nv alu_cond_addmul(str_to_id_cond_addmul(yytext), INST_COND_ADDMUL_NV);
cond_(add|mul)=al alu_cond_addmul(str_to_id_cond_addmul(yytext), INST_COND_ADDMUL_AL);
cond_(add|mul)=zs alu_cond_addmul(str_to_id_cond_addmul(yytext), INST_COND_ADDMUL_ZS);
cond_(add|mul)=zc alu_cond_addmul(str_to_id_cond_addmul(yytext), INST_COND_ADDMUL_ZC);
cond_(add|mul)=ns alu_cond_addmul(str_to_id_cond_addmul(yytext), INST_COND_ADDMUL_NS);
cond_(add|mul)=nc alu_cond_addmul(str_to_id_cond_addmul(yytext), INST_COND_ADDMUL_NC);
cond_(add|mul)=cs alu_cond_addmul(str_to_id_cond_addmul(yytext), INST_COND_ADDMUL_CS);
cond_(add|mul)=cc alu_cond_addmul(str_to_id_cond_addmul(yytext), INST_COND_ADDMUL_CC);

sf=0 alu_sf(INST_SF_0);
sf=1 alu_sf(INST_SF_1);

ws=0 alu_ws(INST_WS_0);
ws=1 alu_ws(INST_WS_1);

[rw]addr_(add|mul|a|b)=ra0 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA0);
[rw]addr_(add|mul|a|b)=rb0 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB0);

[rw]addr_(add|mul|a|b)=ra1 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA1);
[rw]addr_(add|mul|a|b)=rb1 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB1);

[rw]addr_(add|mul|a|b)=ra2 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA2);
[rw]addr_(add|mul|a|b)=rb2 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB2);

[rw]addr_(add|mul|a|b)=ra3 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA3);
[rw]addr_(add|mul|a|b)=rb3 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB3);

[rw]addr_(add|mul|a|b)=ra4 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA4);
[rw]addr_(add|mul|a|b)=rb4 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB4);

[rw]addr_(add|mul|a|b)=ra5 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA5);
[rw]addr_(add|mul|a|b)=rb5 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB5);

[rw]addr_(add|mul|a|b)=ra6 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA6);
[rw]addr_(add|mul|a|b)=rb6 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB6);

[rw]addr_(add|mul|a|b)=ra7 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA7);
[rw]addr_(add|mul|a|b)=rb7 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB7);

[rw]addr_(add|mul|a|b)=ra8 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA8);
[rw]addr_(add|mul|a|b)=rb8 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB8);

[rw]addr_(add|mul|a|b)=ra9 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA9);
[rw]addr_(add|mul|a|b)=rb9 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB9);

[rw]addr_(add|mul|a|b)=ra10 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA10);
[rw]addr_(add|mul|a|b)=rb10 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB10);

[rw]addr_(add|mul|a|b)=ra11 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA11);
[rw]addr_(add|mul|a|b)=rb11 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB11);

[rw]addr_(add|mul|a|b)=ra12 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA12);
[rw]addr_(add|mul|a|b)=rb12 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB12);

[rw]addr_(add|mul|a|b)=ra13 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA13);
[rw]addr_(add|mul|a|b)=rb13 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB13);

[rw]addr_(add|mul|a|b)=ra14 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA14);
[rw]addr_(add|mul|a|b)=rb14 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB14);

[rw]addr_(add|mul|a|b)=ra15 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA15);
[rw]addr_(add|mul|a|b)=rb15 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB15);

[rw]addr_(add|mul|a|b)=ra16 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA16);
[rw]addr_(add|mul|a|b)=rb16 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB16);

[rw]addr_(add|mul|a|b)=ra17 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA17);
[rw]addr_(add|mul|a|b)=rb17 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB17);

[rw]addr_(add|mul|a|b)=ra18 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA18);
[rw]addr_(add|mul|a|b)=rb18 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB18);

[rw]addr_(add|mul|a|b)=ra19 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA19);
[rw]addr_(add|mul|a|b)=rb19 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB19);

[rw]addr_(add|mul|a|b)=ra20 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA20);
[rw]addr_(add|mul|a|b)=rb20 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB20);

[rw]addr_(add|mul|a|b)=ra21 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA21);
[rw]addr_(add|mul|a|b)=rb21 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB21);

[rw]addr_(add|mul|a|b)=ra22 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA22);
[rw]addr_(add|mul|a|b)=rb22 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB22);

[rw]addr_(add|mul|a|b)=ra23 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA23);
[rw]addr_(add|mul|a|b)=rb23 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB23);

[rw]addr_(add|mul|a|b)=ra24 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA24);
[rw]addr_(add|mul|a|b)=rb24 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB24);

[rw]addr_(add|mul|a|b)=ra25 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA25);
[rw]addr_(add|mul|a|b)=rb25 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB25);

[rw]addr_(add|mul|a|b)=ra26 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA26);
[rw]addr_(add|mul|a|b)=rb26 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB26);

[rw]addr_(add|mul|a|b)=ra27 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA27);
[rw]addr_(add|mul|a|b)=rb27 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB27);

[rw]addr_(add|mul|a|b)=ra28 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA28);
[rw]addr_(add|mul|a|b)=rb28 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB28);

[rw]addr_(add|mul|a|b)=ra29 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA29);
[rw]addr_(add|mul|a|b)=rb29 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB29);

[rw]addr_(add|mul|a|b)=ra30 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA30);
[rw]addr_(add|mul|a|b)=rb30 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB30);

[rw]addr_(add|mul|a|b)=ra31 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RA31);
[rw]addr_(add|mul|a|b)=rb31 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_RB31);

[rw]addr_(add|mul|a|b)=uniform_read alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_UNIFORM_READ);
[rw]addr_(add|mul|a|b)=r0 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_R0);

[rw]addr_(add|mul|a|b)=r1 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_R1);

[rw]addr_(add|mul|a|b)=r2 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_R2);

[rw]addr_(add|mul|a|b)=r3 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_R3);

[rw]addr_(add|mul|a|b)=tmu_noswap alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_TMU_NOSWAP);

[rw]addr_(add|mul|a|b)=r5 alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_R5);

[rw]addr_(add|mul|a|b)=element_number alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_ELEMENT_NUMBER);
[rw]addr_(add|mul|a|b)=qpu_number alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_QPU_NUMBER);
[rw]addr_(add|mul|a|b)=host_int alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_HOST_INT);

[rw]addr_(add|mul|a|b)=nop alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_NOP);

[rw]addr_(add|mul|a|b)=uniforms_address alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_UNIFORMS_ADDRESS);

[rw]addr_(add|mul|a|b)=vpm_read alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_VPM_READ);
[rw]addr_(add|mul|a|b)=vpm_write alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_VPM_WRITE);

[rw]addr_(add|mul|a|b)=vpm_ld_busy alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_VPM_LD_BUSY);
[rw]addr_(add|mul|a|b)=vpm_st_busy alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_VPM_ST_BUSY);
[rw]addr_(add|mul|a|b)=vpmvcd_wr_setup alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_VPMVCD_WR_SETUP);
[rw]addr_(add|mul|a|b)=vpmvcd_rd_setup alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_VPMVCD_RD_SETUP);

[rw]addr_(add|mul|a|b)=vpm_ld_wait alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_VPM_LD_WAIT);
[rw]addr_(add|mul|a|b)=vpm_st_wait alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_VPM_ST_WAIT);
[rw]addr_(add|mul|a|b)=vpm_ld_addr alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_VPM_LD_ADDR);
[rw]addr_(add|mul|a|b)=vpm_st_addr alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_VPM_ST_ADDR);

[rw]addr_(add|mul|a|b)=mutex_acquire alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_MUTEX_ACQUIRE);
[rw]addr_(add|mul|a|b)=mutex_release alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_MUTEX_RELEASE);

[rw]addr_(add|mul|a|b)=sfu_recip alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_SFU_RECIP);

[rw]addr_(add|mul|a|b)=sfu_recipsqrt alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_SFU_RECIPSQRT);

[rw]addr_(add|mul|a|b)=sfu_exp alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_SFU_EXP);

[rw]addr_(add|mul|a|b)=sfu_log alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_SFU_LOG);

[rw]addr_(add|mul|a|b)=tmu0s alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_TMU0S);

[rw]addr_(add|mul|a|b)=tmu0t alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_TMU0T);

[rw]addr_(add|mul|a|b)=tmu0r alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_TMU0R);

[rw]addr_(add|mul|a|b)=tmu0b alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_TMU0B);

[rw]addr_(add|mul|a|b)=tmu1s alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_TMU1S);

[rw]addr_(add|mul|a|b)=tmu1t alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_TMU1T);

[rw]addr_(add|mul|a|b)=tmu1r alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_TMU1R);

[rw]addr_(add|mul|a|b)=tmu1b alu_rwaddr_addmulab(str_to_id_rwaddr_addmulab(yytext), INST_RWADDR_ADDMULAB_TMU1B);

simm=0 alu_simm(INST_SIMM_0);
simm=1 alu_simm(INST_SIMM_1);
simm=2 alu_simm(INST_SIMM_2);
simm=3 alu_simm(INST_SIMM_3);
simm=4 alu_simm(INST_SIMM_4);
simm=5 alu_simm(INST_SIMM_5);
simm=6 alu_simm(INST_SIMM_6);
simm=7 alu_simm(INST_SIMM_7);
simm=8 alu_simm(INST_SIMM_8);
simm=9 alu_simm(INST_SIMM_9);
simm=10 alu_simm(INST_SIMM_10);
simm=11 alu_simm(INST_SIMM_11);
simm=12 alu_simm(INST_SIMM_12);
simm=13 alu_simm(INST_SIMM_13);
simm=14 alu_simm(INST_SIMM_14);
simm=15 alu_simm(INST_SIMM_15);
simm=-16 alu_simm(INST_SIMM_M16);
simm=-15 alu_simm(INST_SIMM_M15);
simm=-14 alu_simm(INST_SIMM_M14);
simm=-13 alu_simm(INST_SIMM_M13);
simm=-12 alu_simm(INST_SIMM_M12);
simm=-11 alu_simm(INST_SIMM_M11);
simm=-10 alu_simm(INST_SIMM_M10);
simm=-9 alu_simm(INST_SIMM_M9);
simm=-8 alu_simm(INST_SIMM_M8);
simm=-7 alu_simm(INST_SIMM_M7);
simm=-6 alu_simm(INST_SIMM_M6);
simm=-5 alu_simm(INST_SIMM_M5);
simm=-4 alu_simm(INST_SIMM_M4);
simm=-3 alu_simm(INST_SIMM_M3);
simm=-2 alu_simm(INST_SIMM_M2);
simm=-1 alu_simm(INST_SIMM_M1);
simm=1\.0 alu_simm(INST_SIMM_1F);
simm=2\.0 alu_simm(INST_SIMM_2F);
simm=4\.0 alu_simm(INST_SIMM_4F);
simm=8\.0 alu_simm(INST_SIMM_8F);
simm=16\.0 alu_simm(INST_SIMM_16F);
simm=32\.0 alu_simm(INST_SIMM_32F);
simm=64\.0 alu_simm(INST_SIMM_64F);
simm=128\.0 alu_simm(INST_SIMM_128F);
simm=1(\.0){0,1}\/256(\.0){0,1} alu_simm(INST_SIMM_1_256F);
simm=1(\.0){0,1}\/128(\.0){0,1} alu_simm(INST_SIMM_1_128F);
simm=1(\.0){0,1}\/64(\.0){0,1} alu_simm(INST_SIMM_1_64F);
simm=1(\.0){0,1}\/32(\.0){0,1} alu_simm(INST_SIMM_1_32F);
simm=1(\.0){0,1}\/16(\.0){0,1} alu_simm(INST_SIMM_1_16F);
simm=1(\.0){0,1}\/8(\.0){0,1} alu_simm(INST_SIMM_1_8F);
simm=1(\.0){0,1}\/4(\.0){0,1} alu_simm(INST_SIMM_1_4F);
simm=1(\.0){0,1}\/2(\.0){0,1} alu_simm(INST_SIMM_1_2F);
simm=vrr5 alu_simm(INST_SIMM_VRR5);
simm=vr1 alu_simm(INST_SIMM_VR1);
simm=vr2 alu_simm(INST_SIMM_VR2);
simm=vr3 alu_simm(INST_SIMM_VR3);
simm=vr4 alu_simm(INST_SIMM_VR4);
simm=vr5 alu_simm(INST_SIMM_VR5);
simm=vr6 alu_simm(INST_SIMM_VR6);
simm=vr7 alu_simm(INST_SIMM_VR7);
simm=vr8 alu_simm(INST_SIMM_VR8);
simm=vr9 alu_simm(INST_SIMM_VR9);
simm=vr10 alu_simm(INST_SIMM_VR10);
simm=vr11 alu_simm(INST_SIMM_VR11);
simm=vr12 alu_simm(INST_SIMM_VR12);
simm=vr13 alu_simm(INST_SIMM_VR13);
simm=vr14 alu_simm(INST_SIMM_VR14);
simm=vr15 alu_simm(INST_SIMM_VR15);

(add|mul)_[ab]=r0 alu_addmul_ab(str_to_id_addmul_ab(yytext), INST_ADDMUL_AB_R0);
(add|mul)_[ab]=r1 alu_addmul_ab(str_to_id_addmul_ab(yytext), INST_ADDMUL_AB_R1);
(add|mul)_[ab]=r2 alu_addmul_ab(str_to_id_addmul_ab(yytext), INST_ADDMUL_AB_R2);
(add|mul)_[ab]=r3 alu_addmul_ab(str_to_id_addmul_ab(yytext), INST_ADDMUL_AB_R3);
(add|mul)_[ab]=r4 alu_addmul_ab(str_to_id_addmul_ab(yytext), INST_ADDMUL_AB_R4);
(add|mul)_[ab]=r5 alu_addmul_ab(str_to_id_addmul_ab(yytext), INST_ADDMUL_AB_R5);
(add|mul)_[ab]=ra alu_addmul_ab(str_to_id_addmul_ab(yytext), INST_ADDMUL_AB_RA);
(add|mul)_[ab]=rb alu_addmul_ab(str_to_id_addmul_ab(yytext), INST_ADDMUL_AB_RB);

op_mul=nop alu_op_mul(INST_OP_MUL_NOP);
op_mul=fmul alu_op_mul(INST_OP_MUL_FMUL);
op_mul=mul24 alu_op_mul(INST_OP_MUL_MUL24);
op_mul=v8muld alu_op_mul(INST_OP_MUL_V8MULD);
op_mul=v8min alu_op_mul(INST_OP_MUL_V8MIN);
op_mul=v8max alu_op_mul(INST_OP_MUL_V8MAX);
op_mul=v8adds alu_op_mul(INST_OP_MUL_V8ADDS);
op_mul=v8subs alu_op_mul(INST_OP_MUL_V8SUBS);

op_add=nop alu_op_add(INST_OP_ADD_NOP);
op_add=fadd alu_op_add(INST_OP_ADD_FADD);
op_add=fsub alu_op_add(INST_OP_ADD_FSUB);
op_add=fmin alu_op_add(INST_OP_ADD_FMIN);
op_add=fmax alu_op_add(INST_OP_ADD_FMAX);
op_add=fminabs alu_op_add(INST_OP_ADD_FMINABS);
op_add=fmaxabs alu_op_add(INST_OP_ADD_FMAXABS);
op_add=ftoi alu_op_add(INST_OP_ADD_FTOI);
op_add=itof alu_op_add(INST_OP_ADD_ITOF);
op_add=add alu_op_add(INST_OP_ADD_ADD);
op_add=sub alu_op_add(INST_OP_ADD_SUB);
op_add=shr alu_op_add(INST_OP_ADD_SHR);
op_add=asr alu_op_add(INST_OP_ADD_ASR);
op_add=ror alu_op_add(INST_OP_ADD_ROR);
op_add=shl alu_op_add(INST_OP_ADD_SHL);
op_add=min alu_op_add(INST_OP_ADD_MIN);
op_add=max alu_op_add(INST_OP_ADD_MAX);
op_add=and alu_op_add(INST_OP_ADD_AND);
op_add=or alu_op_add(INST_OP_ADD_OR);
op_add=xor alu_op_add(INST_OP_ADD_XOR);
op_add=not alu_op_add(INST_OP_ADD_NOT);
op_add=clz alu_op_add(INST_OP_ADD_CLZ);
op_add=v8adds alu_op_add(INST_OP_ADD_V8ADDS);
op_add=v8subs alu_op_add(INST_OP_ADD_V8SUBS);

cond_br=allzs bra_cond_br(INST_COND_BR_ALLZS);
cond_br=allzc bra_cond_br(INST_COND_BR_ALLZC);
cond_br=anyzs bra_cond_br(INST_COND_BR_ANYZS);
cond_br=anyzc bra_cond_br(INST_COND_BR_ANYZC);
cond_br=allns bra_cond_br(INST_COND_BR_ALLNS);
cond_br=allnc bra_cond_br(INST_COND_BR_ALLNC);
cond_br=anyns bra_cond_br(INST_COND_BR_ANYNS);
cond_br=anync bra_cond_br(INST_COND_BR_ANYNC);
cond_br=allcs bra_cond_br(INST_COND_BR_ALLCS);
cond_br=allcc bra_cond_br(INST_COND_BR_ALLCC);
cond_br=anycs bra_cond_br(INST_COND_BR_ANYCS);
cond_br=anycc bra_cond_br(INST_COND_BR_ANYCC);
cond_br=al    bra_cond_br(INST_COND_BR_AL   );

rel=0 bra_rel(INST_REL_0);
rel=1 bra_rel(INST_REL_1);

reg=0 bra_reg(INST_REG_0);
reg=1 bra_reg(INST_REG_1);

sa=inc sem_sa(INST_SA_INC);
sa=dec sem_sa(INST_SA_DEC);

sem=0 sem_sem(INST_SEM_0);
sem=1 sem_sem(INST_SEM_1);
sem=2 sem_sem(INST_SEM_2);
sem=3 sem_sem(INST_SEM_3);
sem=4 sem_sem(INST_SEM_4);
sem=5 sem_sem(INST_SEM_5);
sem=6 sem_sem(INST_SEM_6);
sem=7 sem_sem(INST_SEM_7);
sem=8 sem_sem(INST_SEM_8);
sem=9 sem_sem(INST_SEM_9);
sem=10 sem_sem(INST_SEM_10);
sem=11 sem_sem(INST_SEM_11);
sem=12 sem_sem(INST_SEM_12);
sem=13 sem_sem(INST_SEM_13);
sem=14 sem_sem(INST_SEM_14);
sem=15 sem_sem(INST_SEM_15);

^[ \t]*(\n|\r|\r\n) end_of_line(1);
^[ \t]*;.*(\n|\r|\r\n) end_of_line(1);
;.*(\n|\r|\r\n) end_of_line(0);
\n|\r|\r\n end_of_line(0);

. error_invalid_character(*yytext);

%%

static void assemble_init()
{
	line_number = 1;
	program_number = 1;
	inst_reset();
	diskstorage_init(&ds_inst);
	diskstorage_init(&ds_simm_imm_str);
	diskstorage_init(&ds_label);
	diskstorage_init(&ds_label_program_number);
}

static void assemble_finalize()
{
	int i, j, n_inst, n_label, len_max_imm, len_max_label;
	char *label = NULL, *imm_saved = NULL, *imm_new = NULL;

	n_inst = diskstorage_n(&ds_inst);
	if (n_inst != program_number - 1)
		error_q(__FILE__, __LINE__, "error: n_inst(%d) and program_number-1(%d) differ\n", n_inst, program_number - 1);
	n_label = diskstorage_n(&ds_label);
	len_max_imm = diskstorage_len_max(&ds_simm_imm_str);
	len_max_label = diskstorage_len_max(&ds_label);
	label = malloc((len_max_label + 1) * sizeof(char));
	if (label == NULL)
		error_q(__FILE__, __LINE__, "error: Failed to allocate label\n");
	imm_saved = malloc((len_max_imm + 1) * sizeof(char));
	if (imm_saved == NULL)
		error_q(__FILE__, __LINE__, "error: Failed to allocate imm_saved\n");
	imm_new = malloc((len_max_imm + (10 - 2 + 1) + 1) * sizeof(char));
	if (imm_new == NULL)
		error_q(__FILE__, __LINE__, "error: Failed to allocate imm_saved\n");

	diskstorage_seek(0, &ds_inst);
	diskstorage_seek(0, &ds_simm_imm_str);
	for (i = 0; i < n_inst; i ++) {
		program_number = i + 1;
		diskstorage_read_next(&inst, sizeof(inst), &ds_inst);
		if (inst.is_saved.simm || inst.is_saved.imm) {
			int len;
			char *token = NULL, *saveptr = NULL;

			len = diskstorage_read_next(imm_saved, len_max_imm, &ds_simm_imm_str);
			imm_saved[len] = '\0';
			imm_new[0] = '\0';

			token = strtok_r(imm_saved, " \t", &saveptr);
			if (token == NULL)
				error_q(__FILE__, __LINE__, "error: Empty label\n");
			do {
				_Bool is_matched = 0;

				strcat(imm_new, " ");

				if (token[0] != ':') {
					strcat(imm_new, token);
					continue;
				}

				/* Skip a ':'. */
				token ++;

				diskstorage_seek(0, &ds_label);
				diskstorage_seek(0, &ds_label_program_number);
				for (j = 0; j < n_label; j ++) {
					int label_program_number;

					len = diskstorage_read_next(label, len_max_label, &ds_label);
					label[len] = '\0';
					diskstorage_read_next(&label_program_number, sizeof(label_program_number), &ds_label_program_number);

					if (!strcmp(token, label)) {
						char buf[(10 + 1) + 1];
						sprintf(buf, "%d", (label_program_number - (program_number + 4)) * (64 / 8));
						strcat(imm_new, buf);
						is_matched = !0;
						break;
					}
				}
				if (!is_matched)
					error_q(__FILE__, __LINE__, "error: Label \"%s\" is not found\n", token);
			} while ((token = strtok_r(NULL, " \t", &saveptr)) != NULL);

			if (inst.is_saved.simm)
				alu_simm(midimm_to_simm(rpn_to_midimm(imm_new, 0)));
			else
				li_imm(midimm_to_imm(rpn_to_midimm(imm_new, 0)));
		}
		print_inst();
	}

	free(imm_new);
	free(imm_saved);
	free(label);
	diskstorage_finalize(&ds_label_program_number);
	diskstorage_finalize(&ds_label);
	diskstorage_finalize(&ds_simm_imm_str);
	diskstorage_finalize(&ds_inst);
}

static void end_of_line(const _Bool is_comment_only_line)
{
	if (is_comment_only_line) {
		line_number ++;
	} else {
		diskstorage_append(&inst, sizeof(inst), &ds_inst);
		line_number ++;
		program_number ++;
	}
	inst_reset();
}

static void inst_init(inst_inst_t inst_inst)
{
	/* Cannnot use INST_IS_SET here. */
	if (inst.is_set.inst)
		error_q(__FILE__, __LINE__, "error: inst is already set\n");

	inst.inst = inst_inst;

	switch (inst_inst) {
		case INST_ALU:
			inst.sig = INST_SIG_NS;
			inst.unpack = INST_UNPACK_3232;
			inst.pm = 0;
			inst.pack = INST_PACK_3232;
			inst.cond_add = INST_COND_ADDMUL_NV;
			inst.cond_mul = INST_COND_ADDMUL_NV;
			inst.sf = INST_SF_0;
			inst.ws = INST_WS_0;
			inst.waddr_add = INST_RWADDR_ADDMULAB_NOP;
			inst.waddr_mul = INST_RWADDR_ADDMULAB_NOP;
			inst.raddr_a = INST_RWADDR_ADDMULAB_NOP;
			inst.raddr_b = INST_RWADDR_ADDMULAB_NOP;
			inst.op_mul = INST_OP_MUL_NOP;
			inst.op_add = INST_OP_ADD_NOP;
			inst.add_a = INST_ADDMUL_AB_R0;
			inst.add_b = INST_ADDMUL_AB_R0;
			inst.mul_a = INST_ADDMUL_AB_R0;
			inst.mul_b = INST_ADDMUL_AB_R0;
			break;

		case INST_BRA:
			inst.rel = INST_REL_0;
			inst.reg = INST_REG_0;
			/* Notice: Not setting inst.raddr_a since it cannot be NOP. */
			inst.ws = 0;
			inst.waddr_add = INST_RWADDR_ADDMULAB_NOP;
			inst.waddr_mul = INST_RWADDR_ADDMULAB_NOP;
			inst.imm = 0;
			break;

		case INST_LI:
			inst.esig = INST_ESIG_32;
			inst.pm = 0;
			inst.pack = INST_PACK_3232;
			inst.cond_add = INST_COND_ADDMUL_NV;
			inst.cond_mul = INST_COND_ADDMUL_NV;
			inst.sf = 0;
			inst.ws = 0;
			inst.waddr_add = INST_RWADDR_ADDMULAB_NOP;
			inst.waddr_mul = INST_RWADDR_ADDMULAB_NOP;
			inst.imm = 0;
			break;

		case INST_SEM:
			inst.pm = 0;
			inst.pack = INST_PACK_3232;
			inst.cond_add = INST_COND_ADDMUL_NV;
			inst.cond_mul = INST_COND_ADDMUL_NV;
			inst.sf = 0;
			inst.ws = 0;
			inst.waddr_add = INST_RWADDR_ADDMULAB_NOP;
			inst.waddr_mul = INST_RWADDR_ADDMULAB_NOP;
			break;

		default:
			error_q(__FILE__, __LINE__, "error: Unknown inst_inst\n");
	}

	INST_SET(inst);
}

static void inst_reset()
{
	memset(&inst, 0, sizeof(inst));
}

static void alu_sig(inst_sig_t inst_sig)
{
	valid_inst_inst(__LINE__, 1, INST_ALU);
	INST_IS_SET(sig);
	inst.sig = inst_sig;
	INST_SET(sig);
}

static void alu_unpack(inst_unpack_t inst_unpack)
{
	valid_inst_inst(__LINE__, 1, INST_ALU);
	INST_IS_SET(unpack);
	inst.unpack = inst_unpack;
	INST_SET(unpack);
}

static void alu_pm(inst_pm_t inst_pm)
{
	valid_inst_inst(__LINE__, 3, INST_ALU, INST_LI, INST_SEM);
	INST_IS_SET(pm);
	inst.pm = inst_pm;
	INST_SET(pm);
}

static void alu_pack(inst_pack_t inst_pack)
{
	valid_inst_inst(__LINE__, 3, INST_ALU, INST_LI, INST_SEM);
	INST_IS_SET(pack);
	inst.pack = inst_pack;
	INST_SET(pack);
}

static void alu_cond_addmul(id_cond_addmul_t id_cond_addmul_ab, inst_cond_addmul_t inst_cond_addmul)
{
	valid_inst_inst(__LINE__, 3, INST_ALU, INST_LI, INST_SEM);
	switch (id_cond_addmul_ab) {
		case ID_COND_ADDMUL_COND_ADD:
			INST_IS_SET(cond_add);
			inst.cond_add = inst_cond_addmul;
			INST_SET(cond_add);
			break;

		case ID_COND_ADDMUL_COND_MUL:
			INST_IS_SET(cond_mul);
			inst.cond_mul = inst_cond_addmul;
			INST_SET(cond_mul);
			break;
	}
}

static void alu_sf(inst_sf_t inst_sf)
{
	valid_inst_inst(__LINE__, 3, INST_ALU, INST_LI, INST_SEM);
	INST_IS_SET(sf);
	inst.sf = inst_sf;
	INST_SET(sf);
}

static void alu_ws(inst_ws_t inst_ws)
{
	valid_inst_inst(__LINE__, 4, INST_ALU, INST_BRA, INST_LI, INST_SEM);
	INST_IS_SET(ws);
	inst.ws = inst_ws;
	INST_SET(ws);
}

static void alu_rwaddr_addmulab(id_rwaddr_addmulab_t id_rwaddr_addmulab, inst_rwaddr_addmulab_t inst_rwaddr_addmulab)
{
	switch (id_rwaddr_addmulab) {
		case ID_RWADDR_ADDMULAB_WADDR_ADD:
			valid_inst_inst(__LINE__, 4, INST_ALU, INST_BRA, INST_LI, INST_SEM);
			INST_IS_SET(waddr_add);
			inst.waddr_add = inst_rwaddr_addmulab;
			INST_SET(waddr_add);
			break;

		case ID_RWADDR_ADDMULAB_WADDR_MUL:
			valid_inst_inst(__LINE__, 4, INST_ALU, INST_BRA, INST_LI, INST_SEM);
			INST_IS_SET(waddr_mul);
			inst.waddr_mul = inst_rwaddr_addmulab;
			INST_SET(waddr_mul);
			break;

		case ID_RWADDR_ADDMULAB_RADDR_A:
			valid_inst_inst(__LINE__, 2, INST_ALU, INST_BRA);
			INST_IS_SET(raddr_a);
			if ((inst.inst == INST_BRA) && (inst_rwaddr_addmulab > INST_RWADDR_ADDMULAB_RA31))
				error_q(__FILE__, __LINE__, "error: raddr_a of bra only supports regfiles\n");
			inst.raddr_a = inst_rwaddr_addmulab;
			INST_SET(raddr_a);
			break;

		case ID_RWADDR_ADDMULAB_RADDR_B:
			valid_inst_inst(__LINE__, 1, INST_ALU);
			INST_IS_SET(raddr_b);
			inst.raddr_b = inst_rwaddr_addmulab;
			INST_SET(raddr_b);
			break;
	}
}

static void alu_simm(inst_simm_t inst_simm)
{
	valid_inst_inst(__LINE__, 1, INST_ALU);
	if (inst.sig != INST_SIG_SIMM)
		error_q(__FILE__, __LINE__, "error: small immediates are only supported in alu sig=simm\n");
	INST_IS_SET(simm);
	inst.simm = inst_simm;
	INST_SET(simm);
}

static void alu_op_mul(inst_op_mul_t inst_op_mul)
{
	valid_inst_inst(__LINE__, 1, INST_ALU);
	INST_IS_SET(op_mul);
	inst.op_mul = inst_op_mul;
	INST_SET(op_mul);
}

static void alu_op_add(inst_op_add_t inst_op_add)
{
	valid_inst_inst(__LINE__, 1, INST_ALU);
	INST_IS_SET(op_add);
	inst.op_add = inst_op_add;
	INST_SET(op_add);
}

static void alu_addmul_ab(id_addmul_ab_t id_addmul_ab, inst_addmul_ab_t inst_addmul_ab)
{
	valid_inst_inst(__LINE__, 1, INST_ALU);
	switch (id_addmul_ab) {
		case ID_ADDMUL_AB_ADD_A:
			INST_IS_SET(add_a);
			inst.add_a = inst_addmul_ab;
			INST_SET(add_a);
			break;

		case ID_ADDMUL_AB_ADD_B:
			INST_IS_SET(add_b);
			inst.add_b = inst_addmul_ab;
			INST_SET(add_b);
			break;

		case ID_ADDMUL_AB_MUL_A:
			INST_IS_SET(mul_a);
			inst.mul_a = inst_addmul_ab;
			INST_SET(mul_a);
			break;

		case ID_ADDMUL_AB_MUL_B:
			INST_IS_SET(mul_b);
			inst.mul_b = inst_addmul_ab;
			INST_SET(mul_b);
			break;
	}
}

static void bra_cond_br(inst_cond_br_t inst_cond_br)
{
	valid_inst_inst(__LINE__, 1, INST_BRA);
	INST_IS_SET(cond_br);
	inst.cond_br = inst_cond_br;
	INST_SET(cond_br);
}

static void bra_rel(inst_rel_t inst_rel)
{
	valid_inst_inst(__LINE__, 1, INST_BRA);
	INST_IS_SET(rel);
	inst.rel = inst_rel;
	INST_SET(rel);
}

static void bra_reg(inst_reg_t inst_reg)
{
	valid_inst_inst(__LINE__, 1, INST_BRA);
	INST_IS_SET(reg);
	inst.reg = inst_reg;
	INST_SET(reg);
}

static void li_esig(inst_esig_t inst_esig)
{
	valid_inst_inst(__LINE__, 1, INST_LI);
	INST_IS_SET(esig);
	inst.esig = inst_esig;
	INST_SET(esig);
}

static void li_imm(inst_imm_t inst_imm)
{
	valid_inst_inst(__LINE__, 2, INST_BRA, INST_LI);
	INST_IS_SET(imm);
	inst.imm = inst_imm;
	INST_SET(imm);
}

static void sem_sa(inst_sa_t inst_sa)
{
	valid_inst_inst(__LINE__, 1, INST_SEM);
	INST_IS_SET(sa);
	inst.sa = inst_sa;
	INST_SET(sa);
}

static void sem_sem(inst_sem_t inst_sem)
{
	valid_inst_inst(__LINE__, 1, INST_SEM);
	INST_IS_SET(sem);
	inst.sem = inst_sem;
	INST_SET(sem);
}

/* cond_(add|mul) */
static id_cond_addmul_t str_to_id_cond_addmul(const char *str)
{
	if (!strncmp(str, "cond_add", 8))
		return ID_COND_ADDMUL_COND_ADD;
	else if (!strncmp(str, "cond_mul", 8))
		return ID_COND_ADDMUL_COND_MUL;
	else {
		error_q(__FILE__, __LINE__, "error: Invalid token for cond_addmul_t: %s\n", str);
		return ID_COND_ADDMUL_COND_ADD; /* To avoid compiler warnings. Ugly. */
	}
}

/* [rw]addr_(add|mul|a|b) */
static id_rwaddr_addmulab_t str_to_id_rwaddr_addmulab(const char *str)
{
	if (!strncmp(str, "waddr_add", 9))
		return ID_RWADDR_ADDMULAB_WADDR_ADD;
	else if (!strncmp(str, "waddr_mul", 9))
		return ID_RWADDR_ADDMULAB_WADDR_MUL;
	else if (!strncmp(str, "raddr_a", 7))
		return ID_RWADDR_ADDMULAB_RADDR_A;
	else if (!strncmp(str, "raddr_b", 7))
		return ID_RWADDR_ADDMULAB_RADDR_B;
	else {
		error_q(__FILE__, __LINE__, "error: Invalid token for rwaddr_addmul_t: %s\n", str);
		return ID_RWADDR_ADDMULAB_WADDR_ADD; /* To avoid compiler warnings. Ugly. */
	}
}

/* (add|mul)_[ab] */
static id_addmul_ab_t str_to_id_addmul_ab(const char *str)
{
	if (!strncmp(str, "add_a", 5))
		return ID_ADDMUL_AB_ADD_A;
	else if (!strncmp(str, "add_b", 5))
		return ID_ADDMUL_AB_ADD_B;
	else if (!strncmp(str, "mul_a", 5))
		return ID_ADDMUL_AB_MUL_A;
	else if (!strncmp(str, "mul_b", 5))
		return ID_ADDMUL_AB_MUL_B;
	else {
		error_q(__FILE__, __LINE__, "error: Invalid token for addmul_ab_t: %s\n", str);
		return ID_ADDMUL_AB_ADD_A; /* To avoid compiler warnings. Ugly. */
	}
}

static void valid_inst_inst(const int line, const int n, ...)
{
	int i;
	va_list ap;
	_Bool is_matched = 0;

	if (!inst.is_set.inst)
		error_q(__FILE__, __LINE__, "error: inst.inst is not initialized yet\n");

	va_start(ap, n);
	for (i = 0; i < n; i ++) {
		inst_inst_t inst_inst = va_arg(ap, inst_inst_t);
		if (inst.inst == inst_inst) {
			is_matched = !0;
			break;
		}
	}
	va_end(ap);

	if (!is_matched)
		error_q(__FILE__, line, "error: This modifier is not supported in this inst_inst\n");
}

static inst_simm_t midimm_to_simm(midimm_t midimm)
{
	switch (midimm.type) {
		case MIDIMM_TYPE_INT:
			switch (midimm.ival) {
				case 0:
					return INST_SIMM_0;
				case 1:
					return INST_SIMM_1;
				case 2:
					return INST_SIMM_2;
				case 3:
					return INST_SIMM_3;
				case 4:
					return INST_SIMM_4;
				case 5:
					return INST_SIMM_5;
				case 6:
					return INST_SIMM_6;
				case 7:
					return INST_SIMM_7;
				case 8:
					return INST_SIMM_8;
				case 9:
					return INST_SIMM_9;
				case 10:
					return INST_SIMM_10;
				case 11:
					return INST_SIMM_11;
				case 12:
					return INST_SIMM_12;
				case 13:
					return INST_SIMM_13;
				case 14:
					return INST_SIMM_14;
				case 15:
					return INST_SIMM_15;
				case -15:
					return INST_SIMM_M15;
				case -14:
					return INST_SIMM_M14;
				case -13:
					return INST_SIMM_M13;
				case -12:
					return INST_SIMM_M12;
				case -11:
					return INST_SIMM_M11;
				case -10:
					return INST_SIMM_M10;
				case -9:
					return INST_SIMM_M9;
				case -8:
					return INST_SIMM_M8;
				case -7:
					return INST_SIMM_M7;
				case -6:
					return INST_SIMM_M6;
				case -5:
					return INST_SIMM_M5;
				case -4:
					return INST_SIMM_M4;
				case -3:
					return INST_SIMM_M3;
				case -2:
					return INST_SIMM_M2;
				case -1:
					return INST_SIMM_M1;
				default:
					error_q(__FILE__, __LINE__, "error: %" PRId32 " is not convertable to simm\n", midimm.ival);
					break;
			}
			break;

		case MIDIMM_TYPE_FLOAT:
			if (midimm.fval == 1.0)
				return INST_SIMM_1F;
			else if (midimm.fval == 2.0)
				return INST_SIMM_2F;
			else if (midimm.fval == 4.0)
				return INST_SIMM_4F;
			else if (midimm.fval == 8.0)
				return INST_SIMM_8F;
			else if (midimm.fval == 16.0)
				return INST_SIMM_16F;
			else if (midimm.fval == 32.0)
				return INST_SIMM_32F;
			else if (midimm.fval == 64.0)
				return INST_SIMM_64F;
			else if (midimm.fval == 128.0)
				return INST_SIMM_128F;
			else if (midimm.fval == 1.0 / 256)
				return INST_SIMM_1_256F;
			else if (midimm.fval == 1.0 / 128)
				return INST_SIMM_1_128F;
			else if (midimm.fval == 1.0 / 64)
				return INST_SIMM_1_64F;
			else if (midimm.fval == 1.0 / 32)
				return INST_SIMM_1_32F;
			else if (midimm.fval == 1.0 / 16)
				return INST_SIMM_1_16F;
			else if (midimm.fval == 1.0 / 8)
				return INST_SIMM_1_8F;
			else if (midimm.fval == 1.0 / 4)
				return INST_SIMM_1_4F;
			else if (midimm.fval == 1.0 / 2)
				return INST_SIMM_1_2F;
			else
				error_q(__FILE__, __LINE__, "error: %f is not convertable to simm\n", midimm.fval);
			break;
	}

	return INST_SIMM_0; /* To avoid compiler warnings. Ugly. */
}

static inst_imm_t midimm_to_imm(midimm_t midimm)
{
	switch (midimm.type) {
		case MIDIMM_TYPE_INT:
			return midimm.ival;
		case MIDIMM_TYPE_FLOAT:
			return midimm.fval;
	}
}

static midimm_t rpn_to_midimm(const char *rpn_arg, const _Bool to_remove_surrounding_chars)
{
	char *rpn = NULL;
	midimm_t midimm;

	if (to_remove_surrounding_chars)
		rpn = remove_surrounding_chars(rpn_arg);
	else {
		rpn = strdup(rpn_arg);
		if (rpn == NULL)
			error_q(__FILE__, __LINE__, "error: strdup: %s\n", strerror(errno));
	}

	midimm.type = MIDIMM_TYPE_INT;
	if (rpn_calc_do(&(midimm.ival), rpn))
		error_q(__FILE__, __LINE__, "error: On rpn_calc_do\n");

	free(rpn);

	return midimm;
}

static void bra_label_save(const char *str)
{
	int i, n;
	int max_len;
	char *label_cur = NULL, *label = NULL;

	label_cur = remove_trailing_spaces_and_newlines(str);

	max_len = diskstorage_len_max(&ds_label);
	label = malloc((max_len + 1) * sizeof(char));
	if (label == NULL)
		error_q(__FILE__, __LINE__, "error: Failed to allocate label\n");

	n = diskstorage_n(&ds_label);
	diskstorage_seek(0, &ds_label);
	for (i = 0; i < n; i ++) {
		int len;
		len = diskstorage_read_next(label, max_len, &ds_label);
		label[len] = '\0';
		if (!strcmp(label_cur, label))
			error_q(__FILE__, __LINE__, "error: Duplicated label: %s\n", label_cur);
	}

	free(label);
	diskstorage_append(label_cur, strlen(label_cur), &ds_label);
	diskstorage_append(&program_number, sizeof(program_number), &ds_label_program_number);
	free(label_cur);
}

static void alu_simm_rpn_save(const char *str)
{
	char *simm = NULL;

	valid_inst_inst(__LINE__, 1, INST_ALU);
	if (inst.sig != INST_SIG_SIMM)
		error_q(__FILE__, __LINE__, "error: small immediates are only supported in alu sig=simm\n");
	INST_IS_SAVED(simm);
	simm = remove_surrounding_chars(str);
	diskstorage_append(simm, strlen(simm), &ds_simm_imm_str);
	free(simm);
	INST_SAVED(simm);
}

static void li_imm_rpn_save(const char *str)
{
	char *imm = NULL;

	valid_inst_inst(__LINE__, 2, INST_BRA, INST_LI);
	INST_IS_SAVED(imm);
	imm = remove_surrounding_chars(str);
	diskstorage_append(imm, strlen(imm), &ds_simm_imm_str);
	free(imm);
	INST_SAVED(imm);
}

static void alu_simm_save_or_expand(const char *str)
{
	valid_inst_inst(__LINE__, 1, INST_ALU);
	if (inst.sig != INST_SIG_SIMM)
		error_q(__FILE__, __LINE__, "error: small immediates are only supported in alu sig=simm\n");
	if (strchr(str, ':') == NULL)
		alu_simm(midimm_to_simm(rpn_to_midimm(str, 1)));
	else
		alu_simm_rpn_save(str);
}

static void li_imm_save_or_expand(const char *str)
{
	valid_inst_inst(__LINE__, 2, INST_BRA, INST_LI);
	if (strchr(str, ':') == NULL)
		li_imm(midimm_to_imm(rpn_to_midimm(str, 1)));
	else
		li_imm_rpn_save(str);
}

/* Removes [0] and [len - 1] and returns a free(3)'able pointer. */
static char* remove_surrounding_chars(const char *str)
{
	char *retstr = NULL;

	retstr = strdup(str + 1);
	if (retstr == NULL)
		error_q(__FILE__, __LINE__, "error: strdup: %s\n", strerror(errno));
	retstr[strlen(retstr) - 1] = '\0';

	return retstr;
}

static char* remove_trailing_spaces_and_newlines(const char *str)
{
	char *retstr = NULL;
	int len;

	retstr = strdup(str);
	if (retstr == NULL)
		error_q(__FILE__, __LINE__, "error: strdup: %s\n", strerror(errno));

	len = strlen(retstr);
	if ((retstr[len - 2] == '\r') && (retstr[len - 1] == '\n')) {
		retstr[--len] = '\0';
		retstr[--len] = '\0';
	} else if ((retstr[len - 1] == '\r') || (retstr[len - 1] == '\n'))
		retstr[--len] = '\0';

	while ((retstr[len - 1] == ' ') || (retstr[len - 1] == '\t'))
		retstr[--len] = '\0';

	return retstr;
}

static void print_inst()
{
	if (!inst.is_set.inst)
		error_q(__FILE__, __LINE__, "error: inst is not set yet\n");

	switch (inst.inst) {
		case INST_ALU:
			print_bin(inst.sig, 4, 1);
			print_bin(inst.unpack, 3, 1);
			print_bin(inst.pm, 1, 1);
			print_bin(inst.pack, 4, 1);
			print_bin(inst.cond_add, 3, 1);
			print_bin(inst.cond_mul, 3, 1);
			print_bin(inst.sf, 1, 1);
			print_bin(inst.ws, 1, 1);
			print_bin(inst.waddr_add, 6, 1);
			print_bin(inst.waddr_mul, 6, 1);
			print_bin(inst.op_mul, 3, 1);
			print_bin(inst.op_add, 5, 1);
			print_bin(inst.raddr_a, 6, 1);
			if (inst.sig == INST_SIG_SIMM)
				print_bin(inst.simm, 6, 1);
			else
				print_bin(inst.raddr_b, 6, 1);
			print_bin(inst.add_a, 3, 1);
			print_bin(inst.add_b, 3, 1);
			print_bin(inst.mul_a, 3, 1);
			print_bin(inst.mul_b, 3, 0);
			break;

		case INST_BRA:
			print_bin(0xf, 4, 1);
			print_bin(0, 4, 1); /* Don't care? */
			print_bin(inst.cond_br, 4, 1);
			print_bin(inst.rel, 1, 1);
			print_bin(inst.reg, 1, 1);
			print_bin(inst.raddr_a, 5, 1);
			print_bin(inst.ws, 1, 1);
			print_bin(inst.waddr_add, 6, 1);
			print_bin(inst.waddr_mul, 6, 1);
			print_bin(inst.imm, 32, 0);
			break;

		case INST_LI:
			print_bin(0xe, 4, 1);
			print_bin(inst.esig, 3, 1);
			print_bin(inst.pm, 1, 1);
			print_bin(inst.pack, 4, 1);
			print_bin(inst.cond_add, 3, 1);
			print_bin(inst.cond_mul, 3, 1);
			print_bin(inst.sf, 1, 1);
			print_bin(inst.ws, 1, 1);
			print_bin(inst.waddr_add, 6, 1);
			print_bin(inst.waddr_mul, 6, 1);
			print_bin(inst.imm, 32, 0);
			break;

		case INST_SEM:
			print_bin(0x74, 7, 1);
			print_bin(inst.pm, 1, 1);
			print_bin(inst.pack, 4, 1);
			print_bin(inst.cond_add, 3, 1);
			print_bin(inst.cond_mul, 3, 1);
			print_bin(inst.sf, 1, 1);
			print_bin(inst.ws, 1, 1);
			print_bin(inst.waddr_add, 6, 1);
			print_bin(inst.waddr_mul, 6, 1);
			print_bin(0, 27, 1);
			print_bin(inst.sa, 1, 1);
			print_bin(inst.sem, 4, 0);
			break;
	}
	putchar('\n');
}

static void print_bin(const uint64_t u, unsigned int width, const _Bool to_print_space)
{
	if (width == 0)
		return;
	while (width --)
		putchar(u & (1 << width) ? '1' : '0');
	if (to_print_space)
		putchar(' ');
}

static void error_invalid_character(const char c)
{
	error_q(__FILE__, __LINE__, "error: Invalid character: %c\n", c);
}

static void error_q(const char *file, const int line, const char *format, ...)
{
	va_list ap;
	int reti;

	reti = fprintf(stderr, "%s:%d: %d: ", file, line, line_number);
	if (reti < 0)
		abort_assemble(__LINE__);
	va_start(ap, format);
	reti = vfprintf(stderr, format, ap);
	if (reti < 0)
		abort_assemble(__LINE__);
	va_end(ap);

	abort_assemble(line);
}

static void abort_assemble(const int line)
{
	longjmp(jenv, line);
}

int qasm2_assemble_file(FILE *fp)
{
	int val;
	YY_BUFFER_STATE state;

	yyin = fp;
	state = yy_create_buffer(yyin, YY_BUF_SIZE);
	if (state == NULL) {
		error_fl(__FILE__, __LINE__, "error: yy_create_buffer returned NULL\n");
		return 1;
	}
	yy_switch_to_buffer(state);
	if ((val = setjmp(jenv))) {
		error_fl(__FILE__, __LINE__, "error: On %s:%d\n", __FILE__, val);
		return 1;
	}
	assemble_init();
	yylex();
	assemble_finalize();
	yy_delete_buffer(state);
	return 0;
}
