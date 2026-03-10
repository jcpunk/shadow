/*
 * SPDX-FileCopyrightText: 2012 Eric Biederman
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "config.h"

#ifdef ENABLE_SUBIDS

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "getdef.h"
#include "prototypes.h"
#include "shadowlog.h"
#include "subordinateio.h"

/*
 * find_new_sub_gids_deterministic - Assign a subordinate GID range by UID.
 *
 * Calculates a deterministic subordinate GID range for a given UID based
 * on its offset from UID_MIN.  Loads SUB_GID_COUNT from login.defs and
 * writes it back to *range_count on success.
 *
 * BASE FORMULA:
 *   uid_offset     = uid - UID_MIN
 *   logical_offset = uid_offset * SUB_GID_COUNT
 *   start_id       = SUB_GID_MIN + logical_offset
 *   end_id         = start_id + SUB_GID_COUNT - 1
 *
 * DETERMINISTIC-SAFE MODE (default):
 *   All arithmetic overflow is a hard error.  The assigned range must fit
 *   entirely within [SUB_GID_MIN, SUB_GID_MAX].  Allocation is monotonic
 *   and guaranteed non-overlapping.
 *
 * UNSAFE_SUB_GID_DETERMINISTIC_WRAP MODE:
 *   Activated with UNSAFE_SUB_GID_DETERMINISTIC_WRAP yes
 *
 *   WARNING: SECURITY RISK!
 *   WARNING: MAY CAUSE RANGE OVERLAPS!
 *   WARNING: MAY CAUSE CONTAINER ESCAPES!
 *
 *   The subordinate GID space is treated as a ring.  Arithmetic overflow
 *   is normalised via modulo over [SUB_GID_MIN, SUB_GID_MAX].
 *   This means ranges MAY overlap for large UID populations!
 *   Intended only for development, testing, or constrained lab environments.
 *
 * Return 0 on success, -1 if no GIDs are available.
 */
static int find_new_sub_gids_deterministic (uid_t uid,
                                            id_t *range_start,
                                            unsigned long *range_count)
{
	unsigned long uid_min;
	unsigned long sub_gid_min;
	unsigned long sub_gid_max;
	unsigned long uid_offset;
	unsigned long space;
	unsigned long count;
	bool allow_wrap;

	assert (range_start != NULL);
	assert (range_count != NULL);

	uid_min = getdef_ulong ("UID_MIN", 1000UL);
	sub_gid_min = getdef_ulong ("SUB_GID_MIN", 65536UL);
	sub_gid_max = getdef_ulong ("SUB_GID_MAX", 4294967295UL);
	count = getdef_ulong ("SUB_GID_COUNT", 65536UL);
	allow_wrap = getdef_bool  ("UNSAFE_SUB_GID_DETERMINISTIC_WRAP");

	if ((unsigned long)uid < uid_min) {
		fprintf (log_get_logfd (),
		         _("%s: UID %lu is less than UID_MIN %lu,"
		           " cannot calculate deterministic subordinate GIDs\n"),
		         log_get_progname (),
		         (unsigned long)uid, uid_min);
		return -1;
	}

	/*
	 * Validate configuration before using min/max in any arithmetic.
	 * If sub_gid_min > sub_gid_max, the space calculation below would
	 * unsigned-wrap and silently produce a nonsense value.
	 */
	if (sub_gid_min > sub_gid_max || count == 0) {
		fprintf (log_get_logfd (),
		         _("%s: Invalid configuration: SUB_GID_MIN (%lu),"
		           " SUB_GID_MAX (%lu), SUB_GID_COUNT (%lu)\n"),
		         log_get_progname (),
		         sub_gid_min, sub_gid_max, count);
		return -1;
	}

	uid_offset = (unsigned long)uid - uid_min;
	space = sub_gid_max - sub_gid_min + 1;

	/*
	 * A range larger than the entire configured space can never be placed
	 * without overlap, regardless of mode.
	 */
	if (count > space) {
		fprintf (log_get_logfd (),
		         _("%s: Not enough space for any subordinate GIDs"
		           " (SUB_GID_MIN=%lu, SUB_GID_MAX=%lu,"
		           " SUB_GID_COUNT=%lu)\n"),
		         log_get_progname (),
		         sub_gid_min, sub_gid_max, count);
		return -1;
	}

	if (!allow_wrap) {
		/*
		 * DETERMINISTIC-SAFE MODE
		 *
		 * Three overflow guards are required:
		 *
		 *   1. uid_offset * count  -> product
		 *      Overflows for large UIDs or large counts.
		 *
		 *   2. sub_gid_min + product -> start_id
		 *      Overflows when the offset pushes start past UINTMAX_MAX.
		 *
		 *   3. start_id + (count-1) -> end_id
		 *      Overflows when start_id is near UINTMAX_MAX even after
		 *      guards 1 and 2 pass.  Required on platforms where
		 *      uintmax_t is wider than the sub-GID value space.
		 *
		 * Omitting any one leaves a range-escape vector on some
		 * possible arch/config combinations.
		 */
		uintmax_t product = 0;
		uintmax_t start_id = 0;
		uintmax_t end_id = 0;

		if (__builtin_mul_overflow (uid_offset, count, &product)) {
			fprintf (log_get_logfd (),
			         _("%s: Overflow calculating deterministic"
			           " subordinate GID range for UID %lu\n"),
			         log_get_progname (), (unsigned long)uid);
			return -1;
		}

		if (__builtin_add_overflow (sub_gid_min, product, &start_id)) {
			fprintf (log_get_logfd (),
			         _("%s: Overflow calculating deterministic"
			           " subordinate GID range for UID %lu\n"),
			         log_get_progname (), (unsigned long)uid);
			return -1;
		}

		if (__builtin_add_overflow (start_id, count - 1, &end_id)) {
			fprintf (log_get_logfd (),
			         _("%s: Overflow calculating deterministic"
			           " subordinate GID range for UID %lu\n"),
			         log_get_progname (), (unsigned long)uid);
			return -1;
		}

		if (end_id > sub_gid_max) {
			fprintf (log_get_logfd (),
			         _("%s: Deterministic subordinate GID range"
			           " for UID %lu exceeds SUB_GID_MAX (%lu)\n"),
			         log_get_progname (),
			         (unsigned long)uid, sub_gid_max);
			return -1;
		}

		*range_start = (id_t)start_id;
		*range_count = count;
		return 0;
	}

	/*
	 * UNSAFE_SUB_GID_DETERMINISTIC_WRAP MODE
	 *
	 * Promote to uintmax_t before multiplying to avoid truncation on
	 * 32-bit platforms where unsigned long is 32 bits.  The modulo
	 * folds the result back into [0, space) before adding min.
	 */
	uintmax_t logical_offset = (uintmax_t)uid_offset * (uintmax_t)count;

	*range_start = (id_t)(sub_gid_min + (unsigned long)(logical_offset % space));
	*range_count = count;
	return 0;
}

/*
 * find_new_sub_gids_linear - Find an unused subordinate GID range via
 * linear search.
 *
 * Loads SUB_GID_COUNT from login.defs and writes the allocated count back
 * to *range_count on success.
 *
 * Return 0 on success, -1 if no unused GIDs are available.
 */
static int find_new_sub_gids_linear (id_t *range_start, unsigned long *range_count)
{
	unsigned long min, max;
	unsigned long count;
	id_t start;

	assert (range_start != NULL);
	assert (range_count != NULL);

	min = getdef_ulong ("SUB_GID_MIN", 100000UL);
	max = getdef_ulong ("SUB_GID_MAX", 600100000UL);
	count = getdef_ulong ("SUB_GID_COUNT", 65536UL);

	if (count == 0 || min > max || count > (max - min + 1)) {
		(void) fprintf (log_get_logfd(),
			_("%s: Invalid configuration: SUB_GID_MIN (%lu),"
			" SUB_GID_MAX (%lu), SUB_GID_COUNT (%lu)\n"),
			log_get_progname(), min, max, count);
		return -1;
	}

	start = sub_gid_find_free_range(min, max, count);
	if (start == (id_t)-1) {
		fprintf(log_get_logfd(),
		         _("%s: Can't get unique subordinate GID range\n"),
		         log_get_progname());
		SYSLOG(LOG_WARN, "no more available subordinate GIDs on the system");
		return -1;
	}
	*range_start = start;
	*range_count = count;
	return 0;
}

/*
 * find_new_sub_gids - Find a new unused range of subordinate GIDs.
 *
 * Return 0 on success, -1 if no unused GIDs are available.
 */
int find_new_sub_gids (uid_t uid, id_t *range_start, unsigned long *range_count)
{
	if (!range_start || !range_count) {
		errno = EINVAL;
		return -1;
	}

	if (getdef_bool ("SUB_GID_DETERMINISTIC"))
		return find_new_sub_gids_deterministic (uid, range_start, range_count);

	return find_new_sub_gids_linear (range_start, range_count);
}

#else				/* !ENABLE_SUBIDS */
extern int ISO_C_forbids_an_empty_translation_unit;
#endif				/* !ENABLE_SUBIDS */
