/*
 * SPDX-FileCopyrightText: 2012 Eric Biederman
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "config.h"

#ifdef ENABLE_SUBIDS

#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

#include "prototypes.h"
#include "subordinateio.h"
#include "getdef.h"
#include "shadowlog.h"

/*
 * find_new_sub_uids - Find a new unused range of UIDs.
 *
 * If successful, find_new_sub_uids provides a range of unused
 * user IDs in the [SUB_UID_MIN:SUB_UID_MAX] range.
 *
 * When SUB_UID_DETERMINISTIC is enabled, the range is calculated
 * deterministically from the user's UID using the formula:
 *   start = SUB_UID_MIN + ((uid - UID_MIN) * SUB_UID_COUNT)
 *
 * Return 0 on success, -1 if no unused UIDs are available.
 */
int find_new_sub_uids (uid_t uid, id_t *range_start, unsigned long *range_count)
{
	unsigned long min, max;
	unsigned long count;
	id_t start;

	assert (range_start != NULL);
	assert (range_count != NULL);

	min = getdef_ulong ("SUB_UID_MIN", 100000UL);
	max = getdef_ulong ("SUB_UID_MAX", 600100000UL);
	count = getdef_ulong ("SUB_UID_COUNT", 65536);

	if (min > max || count >= max || (min + count - 1) > max) {
		(void) fprintf (log_get_logfd(),
				_("%s: Invalid configuration: SUB_UID_MIN (%lu),"
				  " SUB_UID_MAX (%lu), SUB_UID_COUNT (%lu)\n"),
			log_get_progname(), min, max, count);
		return -1;
	}

	if (getdef_bool ("SUB_UID_DETERMINISTIC")) {
		unsigned long uid_min;
		unsigned long uid_offset;
		unsigned long space;
		bool allow_wrap;

		uid_min = getdef_ulong ("UID_MIN", 1000UL);
		allow_wrap = getdef_bool ("UNSAFE_SUB_UID_DETERMINISTIC_WRAP");

		if ((unsigned long)uid < uid_min) {
			(void) fprintf (log_get_logfd(),
					_("%s: UID %lu is less than UID_MIN %lu,"
					  " cannot calculate deterministic subordinate UIDs\n"),
				log_get_progname(),
				(unsigned long)uid, uid_min);
			return -1;
		}

		uid_offset = uid - uid_min;
		space = max - min + 1;

		if (count > space) {
			(void) fprintf (log_get_logfd(),
					_("%s: Not enough space for any subordinate UIDs"
					  " (SUB_UID_MIN=%lu, SUB_UID_MAX=%lu,"
					  " SUB_UID_COUNT=%lu)\n"),
				log_get_progname(), min, max, count);
			return -1;
		}

		if (!allow_wrap) {
			unsigned long product;
			unsigned long end;

			if (__builtin_mul_overflow(uid_offset, count, &product)) {
				(void) fprintf (log_get_logfd(),
						_("%s: Overflow calculating deterministic"
						  " subordinate UID range for UID %lu\n"),
					log_get_progname(),
					(unsigned long)uid);
				return -1;
			}

			if (__builtin_add_overflow(min, product, &start)) {
				(void) fprintf (log_get_logfd(),
						_("%s: Overflow calculating deterministic"
						  " subordinate UID range for UID %lu\n"),
					log_get_progname(),
					(unsigned long)uid);
				return -1;
			}

			end = (unsigned long)start + count - 1;
			if (end > max) {
				(void) fprintf (log_get_logfd(),
						_("%s: Deterministic subordinate UID range"
						  " for UID %lu exceeds SUB_UID_MAX (%lu)\n"),
					log_get_progname(),
					(unsigned long)uid, max);
				return -1;
			}
		} else {
			/*
			 * WRAP MODE
			 *
			 * WARNING: SECURITY RISK - MAY CAUSE RANGE OVERLAPS!
			 *
			 * Treat the ID space as a ring and normalize the
			 * logical offset using modulo arithmetic.
			 */
			uint64_t logical_offset;

			logical_offset = (uint64_t)uid_offset * (uint64_t)count;
			start = (id_t)(min + (unsigned long)(logical_offset % space));
		}

		*range_start = start;
		*range_count = count;
		return 0;
	}

	start = sub_uid_find_free_range(min, max, count);
	if (start == (id_t)-1) {
		fprintf (log_get_logfd(),
		         _("%s: Can't get unique subordinate UID range\n"),
		         log_get_progname());
		SYSLOG(LOG_WARN, "no more available subordinate UIDs on the system");
		return -1;
	}
	*range_start = start;
	*range_count = count;
	return 0;
}
#else				/* !ENABLE_SUBIDS */
extern int ISO_C_forbids_an_empty_translation_unit;
#endif				/* !ENABLE_SUBIDS */

