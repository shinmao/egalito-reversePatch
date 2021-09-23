#ifndef EGALITO_CONFIG_X86_64_KALI_H
#define EGALITO_CONFIG_X86_64_KALI_H

/* For Kali on x86_64 */

/* common */

/* src */

#define SANDBOX_BASE_ADDRESS    0x40000000
#define JIT_TABLE_SIZE          64 * 0x1000

/* app */

#define PROMPT_COLOR   C_WHITE

/* test */

#define ANALYSIS_JUMPTABLE_MAIN_COUNT              1
#define ANALYSIS_JUMPTABLE_PARSE_EXPRESSION_COUNT  2

#endif

