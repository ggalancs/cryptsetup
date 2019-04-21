/*
 * LUKS - Linux Unified Key Setup v2, reencryption helpers
 *
 * Copyright (C) 2016-2018, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2018, Ondrej Kozina
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "luks2_internal.h"

static int reencrypt_segment_id(struct luks2_hdr *hdr, bool new)
{
	return LUKS2_get_segment_id_by_flag(hdr, new ? "backup-final" : "backup-previous");
}

static json_object *reencrypt_segment(struct luks2_hdr *hdr, unsigned new)
{
	return LUKS2_get_segment_by_flag(hdr, new ? "backup-final" : "backup-previous");
}

json_object *LUKS2_reencrypt_segment_new(struct luks2_hdr *hdr)
{
	return reencrypt_segment(hdr, 1);
}

json_object *LUKS2_reencrypt_segment_old(struct luks2_hdr *hdr)
{
	return reencrypt_segment(hdr, 0);
}

int LUKS2_reencrypt_segment_id_new(struct luks2_hdr *hdr)
{
	return reencrypt_segment_id(hdr, true);
}

int LUKS2_reencrypt_segment_id_old(struct luks2_hdr *hdr)
{
	return reencrypt_segment_id(hdr, false);
}

const char *LUKS2_reencrypt_segment_cipher_new(struct luks2_hdr *hdr)
{
	return json_segment_get_cipher(reencrypt_segment(hdr, 1));
}

const char *LUKS2_reencrypt_segment_cipher_old(struct luks2_hdr *hdr)
{
	return json_segment_get_cipher(reencrypt_segment(hdr, 0));
}

int LUKS2_reencrypt_get_sector_size_new(struct luks2_hdr *hdr)
{
	return json_segment_get_sector_size(reencrypt_segment(hdr, 1));
}

int LUKS2_reencrypt_get_sector_size_old(struct luks2_hdr *hdr)
{
	return json_segment_get_sector_size(reencrypt_segment(hdr, 0));
}

static uint64_t _reencrypt_data_offset(struct luks2_hdr *hdr, unsigned new)
{
	json_object *jobj = reencrypt_segment(hdr, new);
	if (jobj)
		return json_segment_get_offset(jobj, 0);

	return LUKS2_get_data_offset(hdr) << SECTOR_SHIFT;
}

uint64_t LUKS2_reencrypt_get_data_offset_moved(struct luks2_hdr *hdr)
{
	json_object *jobj_segment = LUKS2_get_segment_by_flag(hdr, "backup-moved-segment");

	if (!jobj_segment)
		return 0;

	return json_segment_get_offset(jobj_segment, 0);
}

uint64_t LUKS2_reencrypt_get_data_offset_new(struct luks2_hdr *hdr)
{
	return _reencrypt_data_offset(hdr, 1);
}

uint64_t LUKS2_reencrypt_get_data_offset_old(struct luks2_hdr *hdr)
{
	return _reencrypt_data_offset(hdr, 0);
}

static int _reencrypt_digest(struct luks2_hdr *hdr, unsigned new)
{
	int segment = LUKS2_get_segment_id_by_flag(hdr, new ? "backup-final" : "backup-previous");

	if (segment < 0)
		return segment;

	return LUKS2_digest_by_segment(hdr, segment);
}

int LUKS2_reencrypt_digest_new(struct luks2_hdr *hdr)
{
	return _reencrypt_digest(hdr, 1);
}

int LUKS2_reencrypt_digest_old(struct luks2_hdr *hdr)
{
	return _reencrypt_digest(hdr, 0);
}

/* none, checksums, journal or shift */
const char *LUKS2_reencrypt_protection_type(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_type;
	int ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return NULL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "type", &jobj_type))
		return NULL;

	return json_object_get_string(jobj_type);
}

const char *LUKS2_reencrypt_protection_hash(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_type, *jobj_hash;
	int ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return NULL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "type", &jobj_type))
		return NULL;
	if (strcmp(json_object_get_string(jobj_type), "checksum"))
		return NULL;
	if (!json_object_object_get_ex(jobj_area, "hash", &jobj_hash))
		return NULL;

	return json_object_get_string(jobj_hash);
}

uint32_t LUKS2_reencrypt_protection_sector_size(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_type, *jobj_hash, *jobj_sector_size;
	int ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return 0;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "type", &jobj_type))
		return 0;
	if (strcmp(json_object_get_string(jobj_type), "checksum"))
		return 0;
	if (!json_object_object_get_ex(jobj_area, "hash", &jobj_hash))
		return 0;
	if (!json_object_object_get_ex(jobj_area, "sector_size", &jobj_sector_size))
		return 0;

	return json_object_get_uint32(jobj_sector_size);
}

static json_object *_enc_create_segments_shift_after(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	int reenc_seg, i = 0;
	json_object *jobj_copy, *jobj_seg_new = NULL, *jobj_segs_after = json_object_new_object();
	uint64_t tmp;

	if (!rh->jobj_segs_pre || !jobj_segs_after)
		goto err;

	if (json_segments_count(rh->jobj_segs_pre) == 0)
		return jobj_segs_after;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_pre);
	if (reenc_seg < 0)
		goto err;

	while (i < reenc_seg) {
		jobj_copy = json_segments_get_segment(rh->jobj_segs_pre, i);
		if (!jobj_copy)
			goto err;
		json_object_object_add_by_uint(jobj_segs_after, i++, json_object_get(jobj_copy));
	}

	if (json_object_copy(json_segments_get_segment(rh->jobj_segs_pre, reenc_seg + 1), &jobj_seg_new)) {
		if (json_object_copy(json_segments_get_segment(rh->jobj_segs_pre, reenc_seg), &jobj_seg_new))
			goto err;
		json_segment_remove_flag(jobj_seg_new, "in-reencryption");
		tmp = rh->length;
	} else {
		json_object_object_add(jobj_seg_new, "offset", json_object_new_uint64(rh->offset + data_offset));
		json_object_object_add(jobj_seg_new, "iv_tweak", json_object_new_uint64(rh->offset >> SECTOR_SHIFT));
		tmp = json_segment_get_size(jobj_seg_new, 0) + rh->length;
	}

	/* alter size of new segment, reenc_seg == 0 we're finished */
	json_object_object_add(jobj_seg_new, "size", reenc_seg > 0 ? json_object_new_uint64(tmp) : json_object_new_string("dynamic"));
	log_dbg(cd, "jobj_new_seg_after: %s", json_object_to_json_string_ext(jobj_seg_new, JSON_C_TO_STRING_PRETTY));
	json_object_object_add_by_uint(jobj_segs_after, reenc_seg, jobj_seg_new);

	return jobj_segs_after;
err:
	json_object_put(jobj_segs_after);
	return NULL;
}

static json_object *_enc_create_segments_shift_pre(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	int sg, crypt_seg, i = 0;
	uint64_t segment_size;
	json_object *jobj_seg_shrunk, *jobj_seg_new, *jobj_copy, *jobj_enc_seg = NULL,
		     *jobj_segs_pre = json_object_new_object();

	if (!jobj_segs_pre)
		return NULL;

	crypt_seg = LUKS2_segment_by_type(hdr, "crypt");

	/* FIXME: This is hack. Find proper way to fix it. */
	sg = LUKS2_last_segment_by_type(hdr, "linear");
	if (rh->offset && sg < 0)
		goto err;
	if (sg < 0)
		return jobj_segs_pre;

	jobj_enc_seg = json_segment_create_crypt(data_offset + rh->offset,
						      rh->offset >> SECTOR_SHIFT,
						      &rh->length,
						      LUKS2_reencrypt_segment_cipher_new(hdr),
						      LUKS2_reencrypt_get_sector_size_new(hdr),
						      1);
	log_dbg(cd, "jobj_enc_seg: %s", json_object_to_json_string_ext(jobj_enc_seg, JSON_C_TO_STRING_PRETTY));

	while (i < sg) {
		jobj_copy = LUKS2_get_segment_jobj(hdr, i);
		if (!jobj_copy)
			goto err;
		json_object_object_add_by_uint(jobj_segs_pre, i++, json_object_get(jobj_copy));
	}

	segment_size = LUKS2_segment_size(hdr, sg, 0);
	if (segment_size > rh->length) {
		jobj_seg_shrunk = NULL;
		if (json_object_copy(LUKS2_get_segment_jobj(hdr, sg), &jobj_seg_shrunk))
			goto err;
		json_object_object_add(jobj_seg_shrunk, "size", json_object_new_uint64(segment_size - rh->length));
		json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_seg_shrunk);
		log_dbg(cd, "jobj_seg_shrunk: %s", json_object_to_json_string_ext(jobj_seg_shrunk, JSON_C_TO_STRING_PRETTY));
	}

	json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_enc_seg);
	jobj_enc_seg = NULL; /* see err: label */

	/* first crypt segment after encryption ? */
	if (crypt_seg >= 0) {
		jobj_seg_new = LUKS2_get_segment_jobj(hdr, crypt_seg);
		if (!jobj_seg_new)
			goto err;
		json_object_object_add_by_uint(jobj_segs_pre, sg, json_object_get(jobj_seg_new));
		log_dbg(cd, "jobj_seg_new: %s", json_object_to_json_string_ext(jobj_seg_new, JSON_C_TO_STRING_PRETTY));
	}

	return jobj_segs_pre;
err:
	json_object_put(jobj_enc_seg);
	json_object_put(jobj_segs_pre);

	return NULL;
}

static json_object *LUKS2_create_segment_new(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const struct luks2_reenc_context *rh,
		uint64_t data_offset,
		uint64_t segment_offset,
		uint64_t iv_offset,
		const uint64_t *segment_length)
{
	switch (rh->type) {
	case REENCRYPT:
	case ENCRYPT:
		return json_segment_create_crypt(data_offset + segment_offset,
						  crypt_get_iv_offset(cd) + (iv_offset >> SECTOR_SHIFT),
						  segment_length,
						  LUKS2_reencrypt_segment_cipher_new(hdr),
						  LUKS2_reencrypt_get_sector_size_new(hdr), 0);
	case DECRYPT:
		return json_segment_create_linear(data_offset + segment_offset, segment_length, 0);
	}

	return NULL;
}

static json_object *_reenc_segments_forward_after(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	int reenc_seg;
	json_object *jobj_new_seg_after, *jobj_old_seg,
		    *jobj_segs_after = json_object_new_object();
	uint64_t tmp = rh->offset + rh->length;

	if (!rh->jobj_segs_pre || !jobj_segs_after)
		goto err;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_pre);
	if (reenc_seg < 0)
		return NULL;

	jobj_old_seg = json_segments_get_segment(rh->jobj_segs_pre, reenc_seg + 1);

	/*
	 * if there's no old segment after reencryption, we're done.
	 * Set size to 'dynamic' again.
	 */
	jobj_new_seg_after = LUKS2_create_segment_new(cd, hdr, rh, data_offset, 0, 0, jobj_old_seg ? &tmp : NULL);
	if (!jobj_new_seg_after)
		goto err;
	log_dbg(cd, "jobj_new_seg_after: %s", json_object_to_json_string_ext(jobj_new_seg_after, JSON_C_TO_STRING_PRETTY));
	json_object_object_add_by_uint(jobj_segs_after, 0, jobj_new_seg_after);

	if (jobj_old_seg)
		json_object_object_add_by_uint(jobj_segs_after, 1, json_object_get(jobj_old_seg));

	return jobj_segs_after;
err:
	json_object_put(jobj_segs_after);
	return NULL;
}

static json_object *_reenc_segments_backward_after(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	struct luks2_reenc_context *rh,
	uint64_t data_offset)
{
	int reenc_seg;
	json_object *jobj_new_seg_after, *jobj_old_seg,
		    *jobj_segs_after = json_object_new_object();

	if (!rh->jobj_segs_pre || !jobj_segs_after)
		goto err;

	reenc_seg = json_segments_segment_in_reencrypt(rh->jobj_segs_pre);
	if (reenc_seg < 0)
		return NULL;

	jobj_old_seg = json_segments_get_segment(rh->jobj_segs_pre, reenc_seg - 1);
	if (jobj_old_seg)
		json_object_object_add_by_uint(jobj_segs_after, reenc_seg - 1, json_object_get(jobj_old_seg));
	jobj_new_seg_after = LUKS2_create_segment_new(cd, hdr, rh, data_offset, rh->offset, rh->offset, NULL);
	if (!jobj_new_seg_after)
		goto err;
	log_dbg(cd, "jobj_new_seg_after: %s", json_object_to_json_string_ext(jobj_new_seg_after, JSON_C_TO_STRING_PRETTY));
	json_object_object_add_by_uint(jobj_segs_after, reenc_seg, jobj_new_seg_after);

	return jobj_segs_after;
err:
	json_object_put(jobj_segs_after);
	return NULL;
}

static json_object *LUKS2_create_segment_reenc(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const struct luks2_reenc_context *rh,
		uint64_t data_offset,
		uint64_t segment_offset,
		uint64_t iv_offset,
		const uint64_t *segment_length)
{
	switch (rh->type) {
	case REENCRYPT:
	case ENCRYPT:
		return json_segment_create_crypt(data_offset + segment_offset,
				crypt_get_iv_offset(cd) + (iv_offset >> SECTOR_SHIFT),
				segment_length,
				LUKS2_reencrypt_segment_cipher_new(hdr),
				LUKS2_reencrypt_get_sector_size_new(hdr), 1);
	case DECRYPT:
		return json_segment_create_linear(data_offset + segment_offset, segment_length, 1);
	}

	return NULL;
}

static json_object *LUKS2_create_segment_old(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		const struct luks2_reenc_context *rh,
		uint64_t data_offset,
		uint64_t segment_offset,
		const uint64_t *segment_length)
{
	json_object *jobj_old_seg = NULL;

	switch (rh->type) {
	case REENCRYPT:
	case DECRYPT:
		jobj_old_seg = json_segment_create_crypt(data_offset + segment_offset,
						    crypt_get_iv_offset(cd) + (segment_offset >> SECTOR_SHIFT),
						    segment_length,
						    LUKS2_reencrypt_segment_cipher_old(hdr),
						    LUKS2_reencrypt_get_sector_size_old(hdr),
						    0);
		break;
	case ENCRYPT:
		jobj_old_seg = json_segment_create_linear(data_offset + segment_offset, segment_length, 0);
	}

	return jobj_old_seg;
}

static json_object *_reenc_segments_forward_pre(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t device_size,
		uint64_t data_offset)
{
	json_object *jobj_segs_pre, *jobj_reenc_seg, *jobj_old_seg, *jobj_new_seg;
	unsigned int sg = 0;
	uint64_t tmp = rh->offset + rh->length;

	jobj_segs_pre = json_object_new_object();
	if (!jobj_segs_pre)
		return NULL;

	if (rh->offset) {
		jobj_new_seg = LUKS2_create_segment_new(cd, hdr, rh, data_offset, 0, 0, &rh->offset);
		if (!jobj_new_seg)
			goto err;
		log_dbg(cd, "jobj_new_seg: %s", json_object_to_json_string_ext(jobj_new_seg, JSON_C_TO_STRING_PRETTY));
		json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_new_seg);
	}

	jobj_reenc_seg = LUKS2_create_segment_reenc(cd, hdr, rh, data_offset, rh->offset, rh->offset, &rh->length);
	if (!jobj_reenc_seg)
		goto err;

	log_dbg(cd, "jobj_reenc_seg: %s", json_object_to_json_string_ext(jobj_reenc_seg, JSON_C_TO_STRING_PRETTY));

	json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_reenc_seg);

	if (tmp < device_size) {
		jobj_old_seg = LUKS2_create_segment_old(cd, hdr, rh, data_offset + rh->data_shift, rh->offset + rh->length, NULL);
		if (!jobj_old_seg)
			goto err;
		log_dbg(cd, "jobj_old_seg: %s", json_object_to_json_string_ext(jobj_old_seg, JSON_C_TO_STRING_PRETTY));
		json_object_object_add_by_uint(jobj_segs_pre, sg, jobj_old_seg);
	}

	return jobj_segs_pre;
err:
	json_object_put(jobj_segs_pre);
	return NULL;
}

static json_object *_reenc_segments_backward_pre(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t device_size,
		uint64_t data_offset)
{
	json_object *jobj_reenc_seg, *jobj_new_seg, *jobj_old_seg = NULL,
		    *jobj_segs_pre = json_object_new_object();
	int sg = 0;
	uint64_t tmp = rh->offset + rh->length;

	if (!jobj_segs_pre)
		return NULL;

	if (rh->offset) {
		if (json_object_copy(LUKS2_get_segment_jobj(hdr, 0), &jobj_old_seg))
			goto err;
		json_object_object_add(jobj_old_seg, "size", json_object_new_uint64(rh->offset));

		log_dbg(cd, "jobj_old_seg: %s", json_object_to_json_string_ext(jobj_old_seg, JSON_C_TO_STRING_PRETTY));

		json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_old_seg);
	}

	jobj_reenc_seg = LUKS2_create_segment_reenc(cd, hdr, rh, data_offset, rh->offset, rh->offset, &rh->length);
	if (!jobj_reenc_seg)
		goto err;

	log_dbg(cd, "jobj_reenc_seg: %s", json_object_to_json_string_ext(jobj_reenc_seg, JSON_C_TO_STRING_PRETTY));
	json_object_object_add_by_uint(jobj_segs_pre, sg++, jobj_reenc_seg);

	if (tmp < device_size) {
		jobj_new_seg = LUKS2_create_segment_new(cd, hdr, rh, data_offset, rh->offset + rh->length, rh->offset + rh->length, NULL);
		if (!jobj_new_seg)
			goto err;
		log_dbg(cd, "jobj_new_seg: %s", json_object_to_json_string_ext(jobj_new_seg, JSON_C_TO_STRING_PRETTY));
		json_object_object_add_by_uint(jobj_segs_pre, sg, jobj_new_seg);
	}

	return jobj_segs_pre;
err:
	json_object_put(jobj_segs_pre);
	return NULL;
}

static int LUKS2_reenc_create_segments_pre(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t device_size,
		uint64_t data_offset)
{
	rh->jobj_segs_pre = NULL;

	if (rh->type == ENCRYPT && rh->direction == CRYPT_REENCRYPT_BACKWARD && rh->data_shift && rh->jobj_segment_moved) {
		log_dbg(cd, "Calculating hot segments for encryption with data move.");
		rh->jobj_segs_pre = _enc_create_segments_shift_pre(cd, hdr, rh, data_offset);
	} else if (rh->direction == CRYPT_REENCRYPT_FORWARD) {
		log_dbg(cd, "Calculating hot segments (forward direction).");
		rh->jobj_segs_pre = _reenc_segments_forward_pre(cd, hdr, rh, device_size, data_offset);
	} else if (rh->direction == CRYPT_REENCRYPT_BACKWARD) {
		log_dbg(cd, "Calculating hot segments (backward direction).");
		rh->jobj_segs_pre = _reenc_segments_backward_pre(cd, hdr, rh, device_size, data_offset);
	}

	return rh->jobj_segs_pre ? 0 : -EINVAL;
}

int LUKS2_reenc_create_segments_after(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		struct luks2_reenc_context *rh,
		uint64_t data_offset)
{
	rh->jobj_segs_after = NULL;

	if (rh->type == ENCRYPT && rh->direction == CRYPT_REENCRYPT_BACKWARD && rh->data_shift && rh->jobj_segment_moved) {
		log_dbg(cd, "Calculating 'after' segments for encryption with data move.");
		rh->jobj_segs_after = _enc_create_segments_shift_after(cd, hdr, rh, data_offset);
	} else if (rh->direction == CRYPT_REENCRYPT_FORWARD) {
		log_dbg(cd, "Calculating 'after' segments (forward direction).");
		rh->jobj_segs_after = _reenc_segments_forward_after(cd, hdr, rh, data_offset);
	} else if (rh->direction == CRYPT_REENCRYPT_BACKWARD) {
		log_dbg(cd, "Calculating 'after' segments (backward direction).");
		rh->jobj_segs_after = _reenc_segments_backward_after(cd, hdr, rh, data_offset);
	}

	return rh->jobj_segs_after ? 0 : -EINVAL;
}

int LUKS2_reenc_create_segments(struct crypt_device *cd,
				struct luks2_hdr *hdr,
			        struct luks2_reenc_context *rh,
				uint64_t device_size)
{
	int r;
	//uint64_t data_offset = crypt_get_data_offset(cd) << SECTOR_SHIFT;
	uint64_t data_offset = LUKS2_reencrypt_get_data_offset_new(hdr);

	if ((r = LUKS2_reenc_create_segments_pre(cd, hdr, rh, device_size, data_offset)))
		return r;

	if ((r = LUKS2_reenc_create_segments_after(cd, hdr, rh, data_offset)))
		json_object_put(rh->jobj_segs_pre);

	return r;
}

uint64_t LUKS2_reencrypt_data_shift(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_area, *jobj_data_shift;
	int ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return 0;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);

	json_object_object_get_ex(jobj_keyslot, "area", &jobj_area);
	if (!json_object_object_get_ex(jobj_area, "data_shift", &jobj_data_shift))
		return 0;

	return json_object_get_uint64(jobj_data_shift);
}

const char *LUKS2_reencrypt_mode(struct luks2_hdr *hdr)
{
	json_object *jobj_keyslot, *jobj_mode;
	int ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return NULL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);
	json_object_object_get_ex(jobj_keyslot, "mode", &jobj_mode);

	return json_object_get_string(jobj_mode);
}

int LUKS2_reencrypt_direction(struct luks2_hdr *hdr, crypt_reencrypt_direction_info *di)
{
	const char *value;
	json_object *jobj_keyslot, *jobj_mode;
	int r, ks = LUKS2_find_keyslot(hdr, "reencrypt");

	if (ks < 0)
		return -EINVAL;

	jobj_keyslot = LUKS2_get_keyslot_jobj(hdr, ks);
	json_object_object_get_ex(jobj_keyslot, "direction", &jobj_mode);

	value = json_object_get_string(jobj_mode);

	if (!strcmp(value, "forward")) {
		*di = CRYPT_REENCRYPT_FORWARD;
		r = 0;
	} else if (!strcmp(value, "backward")) {
		*di = CRYPT_REENCRYPT_BACKWARD;
		r = 0;
	} else
		r = -EINVAL;

	return r;
}
