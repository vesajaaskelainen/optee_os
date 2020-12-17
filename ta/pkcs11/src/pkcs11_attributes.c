// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2017-2020, Linaro Limited
 */

#include <assert.h>
#include <inttypes.h>
#include <pkcs11_ta.h>
#include <stdlib.h>
#include <string_ext.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>
#include <util.h>

#include "attributes.h"
#include "handle.h"
#include "object.h"
#include "pkcs11_attributes.h"
#include "pkcs11_helpers.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "sanitize_object.h"
#include "serializer.h"
#include "token_capabilities.h"

/* Byte size of CKA_ID attribute when generated locally */
#define PKCS11_CKA_DEFAULT_SIZE		16

static uint32_t pkcs11_func2ckfm(enum processing_func function)
{
	switch (function) {
	case PKCS11_FUNCTION_DIGEST:
		return PKCS11_CKFM_DIGEST;
	case PKCS11_FUNCTION_GENERATE:
		return PKCS11_CKFM_GENERATE;
	case PKCS11_FUNCTION_GENERATE_PAIR:
		return PKCS11_CKFM_GENERATE_KEY_PAIR;
	case PKCS11_FUNCTION_DERIVE:
		return PKCS11_CKFM_DERIVE;
	case PKCS11_FUNCTION_WRAP:
		return PKCS11_CKFM_WRAP;
	case PKCS11_FUNCTION_UNWRAP:
		return PKCS11_CKFM_UNWRAP;
	case PKCS11_FUNCTION_ENCRYPT:
		return PKCS11_CKFM_ENCRYPT;
	case PKCS11_FUNCTION_DECRYPT:
		return PKCS11_CKFM_DECRYPT;
	case PKCS11_FUNCTION_SIGN:
		return PKCS11_CKFM_SIGN;
	case PKCS11_FUNCTION_VERIFY:
		return PKCS11_CKFM_VERIFY;
	case PKCS11_FUNCTION_SIGN_RECOVER:
		return PKCS11_CKFM_SIGN_RECOVER;
	case PKCS11_FUNCTION_VERIFY_RECOVER:
		return PKCS11_CKFM_VERIFY_RECOVER;
	default:
		return 0;
	}
}

enum pkcs11_rc
check_mechanism_against_processing(struct pkcs11_session *session,
				   enum pkcs11_mechanism_id mechanism_type,
				   enum processing_func function,
				   enum processing_step step)
{
	bool allowed = false;

	switch (step) {
	case PKCS11_FUNC_STEP_INIT:
		switch (function) {
		case PKCS11_FUNCTION_IMPORT:
		case PKCS11_FUNCTION_COPY:
		case PKCS11_FUNCTION_MODIFY:
		case PKCS11_FUNCTION_DESTROY:
			return PKCS11_CKR_OK;
		default:
			break;
		}
		/*
		 * Check that the returned PKCS11_CKFM_* flag from
		 * pkcs11_func2ckfm() is among the ones from
		 * mechanism_supported_flags().
		 */
		allowed = mechanism_supported_flags(mechanism_type) &
			  pkcs11_func2ckfm(function);
		break;

	case PKCS11_FUNC_STEP_ONESHOT:
	case PKCS11_FUNC_STEP_UPDATE:
		if (session->processing->always_authen &&
		    !session->processing->relogged)
			return PKCS11_CKR_USER_NOT_LOGGED_IN;

		if (!session->processing->updated)
			allowed = true;
		else
			allowed = !mechanism_is_one_shot_only(mechanism_type);
		break;

	case PKCS11_FUNC_STEP_FINAL:
		if (session->processing->always_authen &&
		    !session->processing->relogged)
			return PKCS11_CKR_USER_NOT_LOGGED_IN;

		return PKCS11_CKR_OK;

	default:
		TEE_Panic(step);
		break;
	}

	if (!allowed) {
		EMSG("Processing %#x/%s not permitted (%u/%u)",
		     (unsigned int)mechanism_type, id2str_proc(mechanism_type),
		     function, step);
		return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	return PKCS11_CKR_OK;
}

/*
 * Object default boolean attributes as per PKCS#11
 */
static uint8_t *pkcs11_object_default_boolprop(uint32_t attribute)
{
	static const uint8_t bool_true = 1;
	static const uint8_t bool_false;

	switch (attribute) {
	/* As per PKCS#11 default value */
	case PKCS11_CKA_MODIFIABLE:
	case PKCS11_CKA_COPYABLE:
	case PKCS11_CKA_DESTROYABLE:
		return (uint8_t *)&bool_true;
	case PKCS11_CKA_TOKEN:
	case PKCS11_CKA_PRIVATE:
	/* symkey false, privkey: token specific */
	case PKCS11_CKA_SENSITIVE:
		return (uint8_t *)&bool_false;
	/* Token specific default value */
	case PKCS11_CKA_SIGN:
	case PKCS11_CKA_VERIFY:
		return (uint8_t *)&bool_true;
	case PKCS11_CKA_DERIVE:
	case PKCS11_CKA_ENCRYPT:
	case PKCS11_CKA_DECRYPT:
	case PKCS11_CKA_SIGN_RECOVER:
	case PKCS11_CKA_VERIFY_RECOVER:
	case PKCS11_CKA_WRAP:
	case PKCS11_CKA_UNWRAP:
	case PKCS11_CKA_EXTRACTABLE:
	case PKCS11_CKA_WRAP_WITH_TRUSTED:
	case PKCS11_CKA_ALWAYS_AUTHENTICATE:
	case PKCS11_CKA_TRUSTED:
		return (uint8_t *)&bool_false;
	default:
		DMSG("No default for boolprop attribute %#"PRIx32, attribute);
		return NULL;
	}
}

/*
 * Object expects several boolean attributes to be set to a default value
 * or to a validate client configuration value. This function append the input
 * attribute (id/size/value) in the serialized object.
 */
static enum pkcs11_rc pkcs11_import_object_boolprop(struct obj_attrs **out,
						    struct obj_attrs *templ,
						    uint32_t attribute)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint8_t bbool = 0;
	uint32_t size = sizeof(uint8_t);
	void *attr = NULL;

	rc = get_attribute(templ, attribute, &bbool, &size);
	if (rc) {
		if (rc != PKCS11_RV_NOT_FOUND)
			return rc;
		attr = pkcs11_object_default_boolprop(attribute);
		if (!attr)
			return PKCS11_CKR_TEMPLATE_INCOMPLETE;
	} else {
		attr = &bbool;
	}

	/* Boolean attributes are 1byte in the ABI, no alignment issue */
	return add_attribute(out, attribute, attr, sizeof(uint8_t));
}

static enum pkcs11_rc set_mandatory_boolprops(struct obj_attrs **out,
					      struct obj_attrs *temp,
					      uint32_t const *bp,
					      size_t bp_count)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	size_t n = 0;

	for (n = 0; n < bp_count; n++) {
		rc = pkcs11_import_object_boolprop(out, temp, bp[n]);
		if (rc)
			return rc;
	}

	return rc;
}

static enum pkcs11_rc set_mandatory_attributes(struct obj_attrs **out,
					       struct obj_attrs *temp,
					       uint32_t const *bp,
					       size_t bp_count)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	size_t n = 0;

	for (n = 0; n < bp_count; n++) {
		uint32_t size = 0;
		void *value = NULL;

		/* Check attribute exists eventually empty */
		if (get_attribute_ptr(temp, bp[n], &value, &size)) {
			DMSG("Missing attribute %s", id2str_attr(bp[n]));
			return PKCS11_CKR_TEMPLATE_INCOMPLETE;
		}

		rc = add_attribute(out, bp[n], value, size);
		if (rc)
			return rc;
	}

	return rc;
}

static enum pkcs11_rc get_default_value(enum pkcs11_attr_id id, void **value,
					uint32_t *size)
{
	/* should have been taken care of already */
	assert(!pkcs11_attr_is_boolean(id));

	/* All other attributes have an empty default value */
	*value = NULL;
	*size = 0;
	return PKCS11_CKR_OK;
}

static enum pkcs11_rc set_optional_attributes(struct obj_attrs **out,
					      struct obj_attrs *temp,
					      uint32_t const *bp,
					      size_t bp_count)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	size_t n = 0;

	for (n = 0; n < bp_count; n++) {
		uint32_t size = 0;
		void *value = NULL;

		rc = get_attribute_ptr(temp, bp[n], &value, &size);
		if (rc == PKCS11_RV_NOT_FOUND)
			rc = get_default_value(bp[n], &value, &size);
		if (rc)
			return rc;

		rc = add_attribute(out, bp[n], value, size);
		if (rc)
			return rc;
	}

	return rc;
}

/*
 * Below are listed the mandated or optional expected attributes for
 * PKCS#11 storage objects.
 *
 * Note: boolprops (mandated boolean attributes) PKCS11_CKA_ALWAYS_SENSITIVE,
 * and PKCS11_CKA_NEVER_EXTRACTABLE are set by the token, not provided
 * in the client template.
 */

/* PKCS#11 specification for any object (session/token) of the storage */
static const uint32_t pkcs11_any_object_boolprops[] = {
	PKCS11_CKA_TOKEN, PKCS11_CKA_PRIVATE,
	PKCS11_CKA_MODIFIABLE, PKCS11_CKA_COPYABLE, PKCS11_CKA_DESTROYABLE,
};

static const uint32_t pkcs11_any_object_optional[] = {
	PKCS11_CKA_LABEL,
};

/* PKCS#11 specification for raw data object (+pkcs11_any_object_xxx) */
const uint32_t pkcs11_raw_data_optional[] = {
	PKCS11_CKA_OBJECT_ID, PKCS11_CKA_APPLICATION, PKCS11_CKA_VALUE,
};

/* PKCS#11 specification for any key object (+pkcs11_any_object_xxx) */
static const uint32_t pkcs11_any_key_boolprops[] = {
	PKCS11_CKA_DERIVE,
};

static const uint32_t pkcs11_any_key_optional[] = {
	PKCS11_CKA_ID,
	PKCS11_CKA_START_DATE, PKCS11_CKA_END_DATE,
	PKCS11_CKA_ALLOWED_MECHANISMS,
};

/* PKCS#11 specification for any symmetric key (+pkcs11_any_key_xxx) */
static const uint32_t pkcs11_symm_key_boolprops[] = {
	PKCS11_CKA_ENCRYPT, PKCS11_CKA_DECRYPT,
	PKCS11_CKA_SIGN, PKCS11_CKA_VERIFY,
	PKCS11_CKA_WRAP, PKCS11_CKA_UNWRAP,
	PKCS11_CKA_SENSITIVE, PKCS11_CKA_EXTRACTABLE,
	PKCS11_CKA_WRAP_WITH_TRUSTED, PKCS11_CKA_TRUSTED,
};

static const uint32_t pkcs11_symm_key_optional[] = {
	PKCS11_CKA_WRAP_TEMPLATE, PKCS11_CKA_UNWRAP_TEMPLATE,
	PKCS11_CKA_DERIVE_TEMPLATE,
	PKCS11_CKA_VALUE, PKCS11_CKA_VALUE_LEN,
};

/* PKCS#11 specification for any asymmetric public key (+pkcs11_any_key_xxx) */
static const uint32_t pkcs11_public_key_boolprops[] = {
	PKCS11_CKA_ENCRYPT, PKCS11_CKA_VERIFY, PKCS11_CKA_VERIFY_RECOVER,
	PKCS11_CKA_WRAP,
	PKCS11_CKA_TRUSTED,
};

static const uint32_t pkcs11_public_key_mandated[] = {
};

static const uint32_t pkcs11_public_key_optional[] = {
	PKCS11_CKA_SUBJECT, PKCS11_CKA_WRAP_TEMPLATE,
	PKCS11_CKA_PUBLIC_KEY_INFO,
};

/* PKCS#11 specification for any asymmetric private key (+pkcs11_any_key_xxx) */
static const uint32_t pkcs11_private_key_boolprops[] = {
	PKCS11_CKA_DECRYPT, PKCS11_CKA_SIGN, PKCS11_CKA_SIGN_RECOVER,
	PKCS11_CKA_UNWRAP,
	PKCS11_CKA_SENSITIVE, PKCS11_CKA_EXTRACTABLE,
	PKCS11_CKA_WRAP_WITH_TRUSTED, PKCS11_CKA_ALWAYS_AUTHENTICATE,
};

static const uint32_t pkcs11_private_key_mandated[] = {
};

static const uint32_t pkcs11_private_key_optional[] = {
	PKCS11_CKA_SUBJECT, PKCS11_CKA_UNWRAP_TEMPLATE,
	PKCS11_CKA_PUBLIC_KEY_INFO,
};

/* PKCS#11 specification for any RSA key (+pkcs11_public/private_key_xxx) */
static const uint32_t pkcs11_rsa_public_key_mandated[] = {
	PKCS11_CKA_MODULUS_BITS,
};

static const uint32_t pkcs11_rsa_public_key_optional[] = {
	PKCS11_CKA_MODULUS, PKCS11_CKA_PUBLIC_EXPONENT,
};

static const uint32_t pkcs11_rsa_private_key_optional[] = {
	PKCS11_CKA_MODULUS, PKCS11_CKA_PUBLIC_EXPONENT,
	PKCS11_CKA_PRIVATE_EXPONENT,
	PKCS11_CKA_PRIME_1, PKCS11_CKA_PRIME_2,
	PKCS11_CKA_EXPONENT_1, PKCS11_CKA_EXPONENT_2, PKCS11_CKA_COEFFICIENT,
};

/* PKCS#11 specification for any EC key (+pkcs11_public/private_key_xxx) */
static const uint32_t pkcs11_ec_public_key_mandated[] = {
	PKCS11_CKA_EC_PARAMS,
};

static const uint32_t pkcs11_ec_public_key_optional[] = {
	PKCS11_CKA_EC_POINT,
};

static const uint32_t pkcs11_ec_private_key_mandated[] = {
};

static const uint32_t pkcs11_ec_private_key_optional[] = {
	PKCS11_CKA_EC_PARAMS,
	PKCS11_CKA_VALUE,
};

static enum pkcs11_rc create_storage_attributes(struct obj_attrs **out,
						struct obj_attrs *temp)
{
	enum pkcs11_class_id class = PKCS11_CKO_UNDEFINED_ID;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	rc = init_attributes_head(out);
	if (rc)
		return rc;

#ifdef PKCS11_SHEAD_WITH_BOOLPROPS
	set_attributes_in_head(*out);
#endif

	/* Object class is mandatory */
	class = get_class(temp);
	if (class == PKCS11_CKO_UNDEFINED_ID) {
		EMSG("Class attribute not found");

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}
	rc = add_attribute(out, PKCS11_CKA_CLASS, &class, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = set_mandatory_boolprops(out, temp, pkcs11_any_object_boolprops,
				     ARRAY_SIZE(pkcs11_any_object_boolprops));
	if (rc)
		return rc;

	return set_optional_attributes(out, temp, pkcs11_any_object_optional,
				       ARRAY_SIZE(pkcs11_any_object_optional));
}

static enum pkcs11_rc create_genkey_attributes(struct obj_attrs **out,
					       struct obj_attrs *temp)
{
	uint32_t type = PKCS11_CKO_UNDEFINED_ID;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	rc = create_storage_attributes(out, temp);
	if (rc)
		return rc;

	type = get_key_type(temp);
	if (type == PKCS11_CKK_UNDEFINED_ID) {
		EMSG("Key type attribute not found");

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}
	rc = add_attribute(out, PKCS11_CKA_KEY_TYPE, &type, sizeof(uint32_t));
	if (rc)
		return rc;

	rc = set_mandatory_boolprops(out, temp, pkcs11_any_key_boolprops,
				     ARRAY_SIZE(pkcs11_any_key_boolprops));
	if (rc)
		return rc;

	return set_optional_attributes(out, temp, pkcs11_any_key_optional,
				       ARRAY_SIZE(pkcs11_any_key_optional));
}

static enum pkcs11_rc create_symm_key_attributes(struct obj_attrs **out,
						 struct obj_attrs *temp)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	assert(get_class(temp) == PKCS11_CKO_SECRET_KEY);

	rc = create_genkey_attributes(out, temp);
	if (rc)
		return rc;

	assert(get_class(*out) == PKCS11_CKO_SECRET_KEY);

	switch (get_key_type(*out)) {
	case PKCS11_CKK_GENERIC_SECRET:
	case PKCS11_CKK_AES:
	case PKCS11_CKK_MD5_HMAC:
	case PKCS11_CKK_SHA_1_HMAC:
	case PKCS11_CKK_SHA256_HMAC:
	case PKCS11_CKK_SHA384_HMAC:
	case PKCS11_CKK_SHA512_HMAC:
	case PKCS11_CKK_SHA224_HMAC:
		break;
	default:
		EMSG("Invalid key type %#"PRIx32"/%s",
		     get_key_type(*out), id2str_key_type(get_key_type(*out)));

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	rc = set_mandatory_boolprops(out, temp, pkcs11_symm_key_boolprops,
				     ARRAY_SIZE(pkcs11_symm_key_boolprops));
	if (rc)
		return rc;

	return set_optional_attributes(out, temp, pkcs11_symm_key_optional,
				       ARRAY_SIZE(pkcs11_symm_key_optional));
}

static enum pkcs11_rc create_data_attributes(struct obj_attrs **out,
					     struct obj_attrs *temp)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	assert(get_class(temp) == PKCS11_CKO_DATA);

	rc = create_storage_attributes(out, temp);
	if (rc)
		return rc;

	assert(get_class(*out) == PKCS11_CKO_DATA);

	return set_optional_attributes(out, temp, pkcs11_raw_data_optional,
				       ARRAY_SIZE(pkcs11_raw_data_optional));
}

static enum pkcs11_rc create_pub_key_attributes(struct obj_attrs **out,
						struct obj_attrs *temp)
{
	uint32_t const *mandated = NULL;
	uint32_t const *optional = NULL;
	size_t mandated_count = 0;
	size_t optional_count = 0;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	assert(get_class(temp) == PKCS11_CKO_PUBLIC_KEY);

	rc = create_genkey_attributes(out, temp);
	if (rc)
		return rc;

	assert(get_class(*out) == PKCS11_CKO_PUBLIC_KEY);

	rc = set_mandatory_boolprops(out, temp, pkcs11_public_key_boolprops,
				     ARRAY_SIZE(pkcs11_public_key_boolprops));
	if (rc)
		return rc;

	rc = set_mandatory_attributes(out, temp, pkcs11_public_key_mandated,
				      ARRAY_SIZE(pkcs11_public_key_mandated));
	if (rc)
		return rc;

	rc = set_optional_attributes(out, temp, pkcs11_public_key_optional,
				     ARRAY_SIZE(pkcs11_public_key_optional));
	if (rc)
		return rc;

	switch (get_key_type(*out)) {
	case PKCS11_CKK_RSA:
		mandated = pkcs11_rsa_public_key_mandated;
		optional = pkcs11_rsa_public_key_optional;
		mandated_count = ARRAY_SIZE(pkcs11_rsa_public_key_mandated);
		optional_count = ARRAY_SIZE(pkcs11_rsa_public_key_optional);
		break;
	case PKCS11_CKK_EC:
		mandated = pkcs11_ec_public_key_mandated;
		optional = pkcs11_ec_public_key_optional;
		mandated_count = ARRAY_SIZE(pkcs11_ec_public_key_mandated);
		optional_count = ARRAY_SIZE(pkcs11_ec_public_key_optional);
		break;
	default:
		EMSG("Invalid key type %#"PRIx32"/%s",
		     get_key_type(*out), id2str_key_type(get_key_type(*out)));

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	rc = set_mandatory_attributes(out, temp, mandated, mandated_count);
	if (rc)
		return rc;

	return set_optional_attributes(out, temp, optional, optional_count);
}

static enum pkcs11_rc create_priv_key_attributes(struct obj_attrs **out,
						 struct obj_attrs *temp)
{
	uint32_t const *mandated = NULL;
	uint32_t const *optional = NULL;
	size_t mandated_count = 0;
	size_t optional_count = 0;
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	assert(get_class(temp) == PKCS11_CKO_PRIVATE_KEY);

	rc = create_genkey_attributes(out, temp);
	if (rc)
		return rc;

	assert(get_class(*out) == PKCS11_CKO_PRIVATE_KEY);

	rc = set_mandatory_boolprops(out, temp, pkcs11_private_key_boolprops,
				     ARRAY_SIZE(pkcs11_private_key_boolprops));
	if (rc)
		return rc;

	rc = set_mandatory_attributes(out, temp, pkcs11_private_key_mandated,
				      ARRAY_SIZE(pkcs11_private_key_mandated));
	if (rc)
		return rc;

	rc = set_optional_attributes(out, temp, pkcs11_private_key_optional,
				     ARRAY_SIZE(pkcs11_private_key_optional));
	if (rc)
		return rc;

	switch (get_key_type(*out)) {
	case PKCS11_CKK_RSA:
		optional = pkcs11_rsa_private_key_optional;
		optional_count = ARRAY_SIZE(pkcs11_rsa_private_key_optional);
		break;
	case PKCS11_CKK_EC:
		mandated = pkcs11_ec_private_key_mandated;
		optional = pkcs11_ec_private_key_optional;
		mandated_count = ARRAY_SIZE(pkcs11_ec_private_key_mandated);
		optional_count = ARRAY_SIZE(pkcs11_ec_private_key_optional);
		break;
	default:
		EMSG("Invalid key type %#"PRIx32"/%s",
		     get_key_type(*out), id2str_key_type(get_key_type(*out)));

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	rc = set_mandatory_attributes(out, temp, mandated, mandated_count);
	if (rc)
		return rc;

	return set_optional_attributes(out, temp, optional, optional_count);
}

/*
 * Create an attribute list for a new object from a template and a parent
 * object (optional) for an object generation function (generate, copy,
 * derive...).
 *
 * PKCS#11 directives on the supplied template and expected return value:
 * - template has an invalid attribute ID: ATTRIBUTE_TYPE_INVALID
 * - template has an invalid value for an attribute: ATTRIBUTE_VALID_INVALID
 * - template has value for a read-only attribute: ATTRIBUTE_READ_ONLY
 * - template+default+parent => still miss an attribute: TEMPLATE_INCONSISTENT
 *
 * INFO on PKCS11_CMD_COPY_OBJECT:
 * - parent PKCS11_CKA_COPYIABLE=false => return ACTION_PROHIBITED.
 * - template can specify PKCS11_CKA_TOKEN, PKCS11_CKA_PRIVATE,
 *   PKCS11_CKA_MODIFIABLE, PKCS11_CKA_DESTROYABLE.
 * - SENSITIVE can change from false to true, not from true to false.
 * - LOCAL is the parent LOCAL
 */
enum pkcs11_rc
create_attributes_from_template(struct obj_attrs **out, void *template,
				size_t template_size,
				struct obj_attrs *parent __unused,
				enum processing_func function,
				enum pkcs11_mechanism_id mecha,
				enum pkcs11_class_id template_class)
{
	struct obj_attrs *temp = NULL;
	struct obj_attrs *attrs = NULL;
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	uint8_t local = 0;
	uint8_t always_sensitive = 0;
	uint8_t never_extract = 0;
	uint32_t class = PKCS11_UNDEFINED_ID;
	uint32_t type = PKCS11_UNDEFINED_ID;
	uint32_t mechanism_id = PKCS11_CKM_UNDEFINED_ID;

#ifdef DEBUG	/* Sanity: check function argument */
	trace_attributes_from_api_head("template", template, template_size);
	switch (function) {
	case PKCS11_FUNCTION_GENERATE:
	case PKCS11_FUNCTION_GENERATE_PAIR:
	case PKCS11_FUNCTION_IMPORT:
		break;
	case PKCS11_FUNCTION_DERIVE:
		trace_attributes("parent", parent);
		break;
	default:
		TEE_Panic(TEE_ERROR_NOT_SUPPORTED);
	}
#endif

	rc = init_attributes_head(&temp);
	if (rc)
		return rc;

	/* Contribute class and key type based on mechanism & template class */
	if (template_class != PKCS11_CKO_UNDEFINED_ID) {
		switch (mecha) {
		case PKCS11_CKM_GENERIC_SECRET_KEY_GEN:
			class = PKCS11_CKO_SECRET_KEY;
			type = PKCS11_CKK_GENERIC_SECRET;
			break;
		case PKCS11_CKM_AES_KEY_GEN:
			class = PKCS11_CKO_SECRET_KEY;
			type = PKCS11_CKK_AES;
			break;
		case PKCS11_CKM_EC_KEY_PAIR_GEN:
			class = template_class;
			type = PKCS11_CKK_EC;
			break;
		case PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN:
			class = template_class;
			type = PKCS11_CKK_RSA;
			break;
		default:
			EMSG("Unable to define class/type from mechanism");
			rc = PKCS11_CKR_TEMPLATE_INCOMPLETE;
			goto out;
		}
		if (class != PKCS11_UNDEFINED_ID) {
			rc = add_attribute(&temp, PKCS11_CKA_CLASS,
					   &class, sizeof(uint32_t));
			if (rc)
				goto out;
		}
		if (type != PKCS11_UNDEFINED_ID) {
			rc = add_attribute(&temp, PKCS11_CKA_KEY_TYPE,
					   &type, sizeof(uint32_t));
			if (rc)
				goto out;
		}
	}

	rc = sanitize_client_object(&temp, template, template_size, false);
	if (rc)
		goto out;

	if (!sanitize_consistent_class_and_type(temp)) {
		EMSG("Inconsistent class/type");
		rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
		goto out;
	}

	switch (get_class(temp)) {
	case PKCS11_CKO_DATA:
		rc = create_data_attributes(&attrs, temp);
		break;
	case PKCS11_CKO_SECRET_KEY:
		rc = create_symm_key_attributes(&attrs, temp);
		break;
	case PKCS11_CKO_PUBLIC_KEY:
		rc = create_pub_key_attributes(&attrs, temp);
		break;
	case PKCS11_CKO_PRIVATE_KEY:
		rc = create_priv_key_attributes(&attrs, temp);
		break;
	default:
		DMSG("Invalid object class %#"PRIx32"/%s",
		     get_class(temp), id2str_class(get_class(temp)));

		rc = PKCS11_CKR_TEMPLATE_INCONSISTENT;
		break;
	}
	if (rc)
		goto out;

	if (get_attribute(attrs, PKCS11_CKA_LOCAL, NULL, NULL) !=
	    PKCS11_RV_NOT_FOUND)
		goto out;

	if (get_attribute(attrs, PKCS11_CKA_KEY_GEN_MECHANISM, NULL, NULL) !=
	    PKCS11_RV_NOT_FOUND)
		goto out;

	switch (function) {
	case PKCS11_FUNCTION_GENERATE:
	case PKCS11_FUNCTION_GENERATE_PAIR:
		local = PKCS11_TRUE;
		break;
	case PKCS11_FUNCTION_COPY:
		local = get_bool(parent, PKCS11_CKA_LOCAL);
		break;
	case PKCS11_FUNCTION_DERIVE:
	case PKCS11_FUNCTION_IMPORT:
	default:
		local = PKCS11_FALSE;
		break;
	}
	rc = add_attribute(&attrs, PKCS11_CKA_LOCAL, &local, sizeof(local));
	if (rc)
		goto out;

	switch (get_class(attrs)) {
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
		always_sensitive = PKCS11_FALSE;
		never_extract = PKCS11_FALSE;

		switch (function) {
		case PKCS11_FUNCTION_DERIVE:
		case PKCS11_FUNCTION_COPY:
			always_sensitive =
				get_bool(parent, PKCS11_CKA_ALWAYS_SENSITIVE) &&
				get_bool(attrs, PKCS11_CKA_SENSITIVE);
			never_extract = get_bool(parent,
						PKCS11_CKA_NEVER_EXTRACTABLE) &&
					!get_bool(attrs,
						  PKCS11_CKA_EXTRACTABLE);
			break;
		case PKCS11_FUNCTION_GENERATE:
			always_sensitive = get_bool(attrs,
						    PKCS11_CKA_SENSITIVE);
			never_extract = !get_bool(attrs,
						  PKCS11_CKA_EXTRACTABLE);
			break;
		default:
			break;
		}

		rc = add_attribute(&attrs, PKCS11_CKA_ALWAYS_SENSITIVE,
				   &always_sensitive, sizeof(always_sensitive));
		if (rc)
			goto out;

		rc = add_attribute(&attrs, PKCS11_CKA_NEVER_EXTRACTABLE,
				   &never_extract, sizeof(never_extract));
		if (rc)
			goto out;

		/* Keys mandate attribute PKCS11_CKA_KEY_GEN_MECHANISM */
		if (function == PKCS11_FUNCTION_COPY) {
			uint32_t sz = 0;

			rc = get_attribute(parent, PKCS11_CKA_KEY_GEN_MECHANISM,
					   &mechanism_id, &sz);
			assert(sz == sizeof(mechanism_id));
			if (rc)
				goto out;
		} else if (local) {
			mechanism_id = mecha;
		} else {
			mechanism_id = PKCS11_CK_UNAVAILABLE_INFORMATION;
		}
		rc = add_attribute(&attrs, PKCS11_CKA_KEY_GEN_MECHANISM,
				   &mechanism_id, sizeof(mechanism_id));
		if (rc)
			goto out;
		break;

	default:
		break;
	}

	*out = attrs;

#ifdef DEBUG
	trace_attributes("object", attrs);
#endif

out:
	TEE_Free(temp);
	if (rc)
		TEE_Free(attrs);

	return rc;
}

static enum pkcs11_rc check_attrs_misc_integrity(struct obj_attrs *head)
{
	if (get_bool(head, PKCS11_CKA_NEVER_EXTRACTABLE) &&
	    get_bool(head, PKCS11_CKA_EXTRACTABLE)) {
		DMSG("Never/Extractable attributes mismatch %d/%d",
		     get_bool(head, PKCS11_CKA_NEVER_EXTRACTABLE),
		     get_bool(head, PKCS11_CKA_EXTRACTABLE));

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	if (get_bool(head, PKCS11_CKA_ALWAYS_SENSITIVE) &&
	    !get_bool(head, PKCS11_CKA_SENSITIVE)) {
		DMSG("Sensitive/always attributes mismatch %d/%d",
		     get_bool(head, PKCS11_CKA_SENSITIVE),
		     get_bool(head, PKCS11_CKA_ALWAYS_SENSITIVE));

		return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	return PKCS11_CKR_OK;
}

/*
 * Check access to object against authentication to token
 */
enum pkcs11_rc check_access_attrs_against_token(struct pkcs11_session *session,
						struct obj_attrs *head)
{
	bool private = true;

	switch (get_class(head)) {
	case PKCS11_CKO_SECRET_KEY:
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_DATA:
		private = get_bool(head, PKCS11_CKA_PRIVATE);
		break;
	case PKCS11_CKO_PRIVATE_KEY:
		break;
	default:
		return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	if (private && pkcs11_session_is_public(session)) {
		DMSG("Private object access from a public session");

		return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	/*
	 * TODO: START_DATE and END_DATE: complies with current time?
	 */
	return PKCS11_CKR_OK;
}

/*
 * Check the attributes of a to-be-created object matches the token state
 */
enum pkcs11_rc check_created_attrs_against_token(struct pkcs11_session *session,
						 struct obj_attrs *head)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;

	rc = check_attrs_misc_integrity(head);
	if (rc)
		return rc;

	if (get_bool(head, PKCS11_CKA_TRUSTED) &&
	    !pkcs11_session_is_so(session)) {
		DMSG("Can't create trusted object");

		return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	if (get_bool(head, PKCS11_CKA_TOKEN) &&
	    !pkcs11_session_is_read_write(session)) {
		DMSG("Can't create persistent object");

		return PKCS11_CKR_SESSION_READ_ONLY;
	}

	/*
	 * TODO: START_DATE and END_DATE: complies with current time?
	 */
	return PKCS11_CKR_OK;
}

/*
 * Check the attributes of new secret match the requirements of the parent key.
 */
enum pkcs11_rc check_created_attrs_against_parent_key(
				uint32_t proc_id __unused,
				struct obj_attrs *parent __unused,
				struct obj_attrs *head __unused)
{
	/*
	 * TODO
	 * Depends on the processing§/mechanism used.
	 * Wrapping: check head vs parent key WRAP_TEMPLATE attribute.
	 * Unwrapping: check head vs parent key UNWRAP_TEMPLATE attribute.
	 * Derive: check head vs parent key DERIVE_TEMPLATE attribute.
	 */
	return PKCS11_CKR_GENERAL_ERROR;
}

#define DMSG_BAD_BBOOL(attr, proc, head)				\
	do {								\
		uint32_t __maybe_unused _attr = (attr);			\
		uint8_t __maybe_unused _bvalue = 0;			\
		enum pkcs11_rc __maybe_unused _rc = PKCS11_CKR_OK;	\
									\
		_rc = get_attribute((head), _attr, &_bvalue, NULL);	\
		DMSG("%s issue for %s: %sfound, value %"PRIu8,		\
		     id2str_attr(_attr), id2str_proc((proc)),		\
		     _rc ? "not " : "", _bvalue);			\
	} while (0)

static bool __maybe_unused check_attr_bval(uint32_t proc_id __maybe_unused,
					   struct obj_attrs *head,
					   uint32_t attribute, bool val)
{
	uint8_t bbool = 0;
	uint32_t sz = sizeof(bbool);

	if (!get_attribute(head, attribute, &bbool, &sz) && !!bbool == val)
		return true;

	DMSG_BAD_BBOOL(attribute, proc_id, head);
	return false;
}

/*
 * Check the attributes of a new secret match the processing/mechanism
 * used to create it.
 *
 * @proc_id - PKCS11_CKM_xxx
 * @head - head of the attributes of the to-be-created object.
 */
enum pkcs11_rc check_created_attrs_against_processing(uint32_t proc_id,
						      struct obj_attrs *head)
{
	/*
	 * Processings that do not create secrets are not expected to call
	 * this function which would panic.
	 */
	switch (proc_id) {
	case PKCS11_PROCESSING_IMPORT:
	case PKCS11_CKM_ECDH1_DERIVE:
	case PKCS11_CKM_ECDH1_COFACTOR_DERIVE:
	case PKCS11_CKM_DH_PKCS_DERIVE:
		assert(check_attr_bval(proc_id, head, PKCS11_CKA_LOCAL, false));
		break;
	case PKCS11_CKM_GENERIC_SECRET_KEY_GEN:
	case PKCS11_CKM_AES_KEY_GEN:
	case PKCS11_CKM_EC_KEY_PAIR_GEN:
	case PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN:
		assert(check_attr_bval(proc_id, head, PKCS11_CKA_LOCAL, true));
		break;
	default:
		TEE_Panic(proc_id);
		break;
	}

	switch (proc_id) {
	case PKCS11_CKM_GENERIC_SECRET_KEY_GEN:
		if (get_key_type(head) != PKCS11_CKK_GENERIC_SECRET)
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		break;
	case PKCS11_CKM_AES_KEY_GEN:
		if (get_key_type(head) != PKCS11_CKK_AES)
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		break;
	case PKCS11_CKM_EC_KEY_PAIR_GEN:
		if (get_key_type(head) != PKCS11_CKK_EC)
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		break;
	case PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN:
		if (get_key_type(head) != PKCS11_CKK_RSA)
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		break;
	case PKCS11_CKM_ECDH1_DERIVE:
	case PKCS11_CKM_ECDH1_COFACTOR_DERIVE:
	case PKCS11_CKM_DH_PKCS_DERIVE:
		if (get_class(head) != PKCS11_CKO_SECRET_KEY)
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		break;
	case PKCS11_PROCESSING_IMPORT:
	default:
		break;
	}

	return PKCS11_CKR_OK;
}

static void get_key_min_max_sizes(enum pkcs11_key_type key_type,
				  uint32_t *min_key_size,
				  uint32_t *max_key_size)
{
	enum pkcs11_mechanism_id mechanism = PKCS11_CKM_UNDEFINED_ID;

	switch (key_type) {
	case PKCS11_CKK_GENERIC_SECRET:
		mechanism = PKCS11_CKM_GENERIC_SECRET_KEY_GEN;
		break;
	case PKCS11_CKK_MD5_HMAC:
		mechanism = PKCS11_CKM_MD5_HMAC;
		break;
	case PKCS11_CKK_SHA_1_HMAC:
		mechanism = PKCS11_CKM_SHA_1_HMAC;
		break;
	case PKCS11_CKK_SHA224_HMAC:
		mechanism = PKCS11_CKM_SHA224_HMAC;
		break;
	case PKCS11_CKK_SHA256_HMAC:
		mechanism = PKCS11_CKM_SHA256_HMAC;
		break;
	case PKCS11_CKK_SHA384_HMAC:
		mechanism = PKCS11_CKM_SHA384_HMAC;
		break;
	case PKCS11_CKK_SHA512_HMAC:
		mechanism = PKCS11_CKM_SHA512_HMAC;
		break;
	case PKCS11_CKK_AES:
		mechanism = PKCS11_CKM_AES_KEY_GEN;
		break;
	case PKCS11_CKK_EC:
		mechanism = PKCS11_CKM_EC_KEY_PAIR_GEN;
		break;
	case PKCS11_CKK_RSA:
	case PKCS11_CKK_DSA:
	case PKCS11_CKK_DH:
		mechanism = PKCS11_CKM_RSA_PKCS_KEY_PAIR_GEN;
		break;
	default:
		TEE_Panic(key_type);
		break;
	}

	mechanism_supported_key_sizes(mechanism, min_key_size,
				      max_key_size);
}

enum pkcs11_rc check_created_attrs(struct obj_attrs *key1,
				   struct obj_attrs *key2)
{
	enum pkcs11_rc rc = PKCS11_CKR_OK;
	struct obj_attrs *secret = NULL;
	struct obj_attrs *private = NULL;
	struct obj_attrs *public = NULL;
	uint32_t max_key_size = 0;
	uint32_t min_key_size = 0;
	uint32_t key_length = 0;

	switch (get_class(key1)) {
	case PKCS11_CKO_SECRET_KEY:
		secret = key1;
		break;
	case PKCS11_CKO_PUBLIC_KEY:
		public = key1;
		break;
	case PKCS11_CKO_PRIVATE_KEY:
		private = key1;
		break;
	default:
		return PKCS11_CKR_ATTRIBUTE_VALUE_INVALID;
	}

	if (key2) {
		switch (get_class(key2)) {
		case PKCS11_CKO_PUBLIC_KEY:
			public = key2;
			if (private == key1)
				break;

			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		case PKCS11_CKO_PRIVATE_KEY:
			private = key2;
			if (public == key1)
				break;

			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		default:
			return PKCS11_CKR_ATTRIBUTE_VALUE_INVALID;
		}

		if (get_key_type(private) != get_key_type(public))
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}

	if (secret) {
		switch (get_key_type(secret)) {
		case PKCS11_CKK_AES:
		case PKCS11_CKK_GENERIC_SECRET:
		case PKCS11_CKK_MD5_HMAC:
		case PKCS11_CKK_SHA_1_HMAC:
		case PKCS11_CKK_SHA224_HMAC:
		case PKCS11_CKK_SHA256_HMAC:
		case PKCS11_CKK_SHA384_HMAC:
		case PKCS11_CKK_SHA512_HMAC:
			break;
		default:
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		}

		/* Get key size */
		rc = get_u32_attribute(secret, PKCS11_CKA_VALUE_LEN,
				       &key_length);
		if (rc)
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
	}
	if (public) {
		switch (get_key_type(public)) {
		case PKCS11_CKK_RSA:
		case PKCS11_CKK_DSA:
		case PKCS11_CKK_DH:
			/* Get key size */
			rc = get_u32_attribute(public, PKCS11_CKA_MODULUS_BITS,
					       &key_length);
			if (rc)
				return PKCS11_CKR_TEMPLATE_INCONSISTENT;
			break;
		case PKCS11_CKK_EC:
			break;
		default:
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		}
	}
	if (private) {
		switch (get_key_type(private)) {
		case PKCS11_CKK_RSA:
		case PKCS11_CKK_DSA:
		case PKCS11_CKK_DH:
			/* Get key size, if key pair public carries bit size */
			if (public)
				break;

			rc = get_u32_attribute(private, PKCS11_CKA_MODULUS_BITS,
					       &key_length);
			if (rc)
				return PKCS11_CKR_TEMPLATE_INCONSISTENT;
			break;
		case PKCS11_CKK_EC:
			/* No need to get key size */
			break;
		default:
			return PKCS11_CKR_TEMPLATE_INCONSISTENT;
		}
	}

	/*
	 * Check key size for symmetric keys and RSA keys
	 * EC is bound to domains, no need to check here.
	 */
	switch (get_key_type(key1)) {
	case PKCS11_CKK_EC:
		return PKCS11_CKR_OK;
	default:
		break;
	}

	get_key_min_max_sizes(get_key_type(key1), &min_key_size, &max_key_size);
	if (key_length < min_key_size || key_length > max_key_size) {
		EMSG("Length %"PRIu32" vs range [%"PRIu32" %"PRIu32"]",
		     key_length, min_key_size, max_key_size);

		return PKCS11_CKR_KEY_SIZE_RANGE;
	}

	return PKCS11_CKR_OK;
}

/* Check processing ID against attribute ALLOWED_MECHANISMS if any */
static bool parent_key_complies_allowed_processings(uint32_t proc_id,
						    struct obj_attrs *head)
{
	char *attr = NULL;
	uint32_t size = 0;
	uint32_t proc = 0;
	size_t count = 0;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;

	/*
	 * Check only if restricted allowed mechanisms list is defined
	 * (FIXME: ALLOWED_MECHANISMS should always be found!!!)
	 */
	rc = get_attribute_ptr(head, PKCS11_CKA_ALLOWED_MECHANISMS,
			       (void *)&attr, &size);
	switch (rc) {
	case PKCS11_RV_NOT_FOUND:
		return true;
	case PKCS11_CKR_OK:
		break;
	default:
		TEE_Panic(0);
	}
	if (!attr)
		return true;

	for (count = size / sizeof(uint32_t); count; count--) {
		TEE_MemMove(&proc, attr, sizeof(uint32_t));
		attr += sizeof(uint32_t);

		if (proc == proc_id)
			return true;
	}

	DMSG("can't find %s in allowed list", id2str_proc(proc_id));
	return false;
}

static enum pkcs11_attr_id func_to_attr(enum processing_func func)
{
	switch (func) {
	case PKCS11_FUNCTION_ENCRYPT:
		return PKCS11_CKA_ENCRYPT;
	case PKCS11_FUNCTION_DECRYPT:
		return PKCS11_CKA_DECRYPT;
	case PKCS11_FUNCTION_SIGN:
		return PKCS11_CKA_SIGN;
	case PKCS11_FUNCTION_VERIFY:
		return PKCS11_CKA_VERIFY;
	case PKCS11_FUNCTION_WRAP:
		return PKCS11_CKA_WRAP;
	case PKCS11_FUNCTION_UNWRAP:
		return PKCS11_CKA_UNWRAP;
	case PKCS11_FUNCTION_DERIVE:
		return PKCS11_CKA_DERIVE;
	default:
		return PKCS11_CKA_UNDEFINED_ID;
	}
}

enum pkcs11_rc
check_parent_attrs_against_processing(enum pkcs11_mechanism_id proc_id,
				      enum processing_func function,
				      struct obj_attrs *head)
{
	enum pkcs11_class_id key_class = get_class(head);
	enum pkcs11_key_type key_type = get_key_type(head);
	enum pkcs11_attr_id attr = func_to_attr(function);

	if (!get_bool(head, attr)) {
		DMSG("%s not permitted", id2str_attr(attr));
		return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	/* Check processing complies with parent key family */
	switch (proc_id) {
	case PKCS11_CKM_AES_ECB:
	case PKCS11_CKM_AES_CBC:
	case PKCS11_CKM_AES_CBC_PAD:
	case PKCS11_CKM_AES_CTS:
	case PKCS11_CKM_AES_CTR:
	case PKCS11_CKM_AES_GCM:
	case PKCS11_CKM_AES_CCM:
	case PKCS11_CKM_AES_CMAC:
	case PKCS11_CKM_AES_CMAC_GENERAL:
	case PKCS11_CKM_AES_XCBC_MAC:
		if (key_class == PKCS11_CKO_SECRET_KEY &&
		    key_type == PKCS11_CKK_AES)
			break;

		DMSG("%s invalid key %s/%s", id2str_proc(proc_id),
		     id2str_class(key_class), id2str_key_type(key_type));

		return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;

	case PKCS11_CKM_MD5_HMAC:
	case PKCS11_CKM_SHA_1_HMAC:
	case PKCS11_CKM_SHA224_HMAC:
	case PKCS11_CKM_SHA256_HMAC:
	case PKCS11_CKM_SHA384_HMAC:
	case PKCS11_CKM_SHA512_HMAC:
		if (key_class != PKCS11_CKO_SECRET_KEY)
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;

		if (key_type == PKCS11_CKK_GENERIC_SECRET)
			break;

		switch (proc_id) {
		case PKCS11_CKM_MD5_HMAC:
			if (key_type == PKCS11_CKK_MD5_HMAC)
				break;
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case PKCS11_CKM_SHA_1_HMAC:
			if (key_type == PKCS11_CKK_SHA_1_HMAC)
				break;
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case PKCS11_CKM_SHA224_HMAC:
			if (key_type == PKCS11_CKK_SHA224_HMAC)
				break;
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case PKCS11_CKM_SHA256_HMAC:
			if (key_type == PKCS11_CKK_SHA256_HMAC)
				break;
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case PKCS11_CKM_SHA384_HMAC:
			if (key_type == PKCS11_CKK_SHA384_HMAC)
				break;
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		case PKCS11_CKM_SHA512_HMAC:
			if (key_type == PKCS11_CKK_SHA512_HMAC)
				break;
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		default:
			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		}
		break;

	case PKCS11_CKM_ECDSA:
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
	case PKCS11_CKM_ECDH1_DERIVE:
	case PKCS11_CKM_ECDH1_COFACTOR_DERIVE:
	case PKCS11_CKM_ECMQV_DERIVE:
	case PKCS11_CKM_ECDH_AES_KEY_WRAP:
		if (key_type != PKCS11_CKK_EC) {
			EMSG("Invalid key %s for mechanism %s",
			     id2str_type(key_type, key_class),
			     id2str_proc(proc_id));

			return PKCS11_CKR_KEY_TYPE_INCONSISTENT;
		}
		if (key_class != PKCS11_CKO_PUBLIC_KEY &&
		    key_class != PKCS11_CKO_PRIVATE_KEY) {
			EMSG("Invalid key class for mechanism %s",
			     id2str_proc(proc_id));

			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		}
		break;

	case PKCS11_CKM_RSA_PKCS:
	case PKCS11_CKM_RSA_9796:
	case PKCS11_CKM_RSA_X_509:
	case PKCS11_CKM_SHA1_RSA_PKCS:
	case PKCS11_CKM_RSA_PKCS_OAEP:
	case PKCS11_CKM_SHA1_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA256_RSA_PKCS:
	case PKCS11_CKM_SHA384_RSA_PKCS:
	case PKCS11_CKM_SHA512_RSA_PKCS:
	case PKCS11_CKM_SHA256_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA384_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA512_RSA_PKCS_PSS:
	case PKCS11_CKM_SHA224_RSA_PKCS:
	case PKCS11_CKM_SHA224_RSA_PKCS_PSS:
	case PKCS11_CKM_RSA_AES_KEY_WRAP:
		if (key_type != PKCS11_CKK_RSA) {
			EMSG("Invalid key %s for mechanism %s",
			     id2str_type(key_type, key_class),
			     id2str_proc(proc_id));

			return PKCS11_CKR_KEY_TYPE_INCONSISTENT;
		}
		if (key_class != PKCS11_CKO_PUBLIC_KEY &&
		    key_class != PKCS11_CKO_PRIVATE_KEY) {
			EMSG("Invalid key class for mechanism %s",
			     id2str_proc(proc_id));

			return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
		}
		break;

	default:
		DMSG("Invalid processing %#"PRIx32"/%s", proc_id,
		     id2str_proc(proc_id));

		return PKCS11_CKR_MECHANISM_INVALID;
	}

	if (!parent_key_complies_allowed_processings(proc_id, head)) {
		DMSG("Allowed mechanism failed");
		return PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	return PKCS11_CKR_OK;
}

bool object_is_private(struct obj_attrs *head)
{
	if (get_class(head) == PKCS11_CKO_PRIVATE_KEY)
		return true;

	if (get_bool(head, PKCS11_CKA_PRIVATE))
		return true;

	return false;
}

bool object_is_modifiable(struct obj_attrs *head)
{
	return get_bool(head, PKCS11_CKA_MODIFIABLE);
}

/*
 * Add a CKA ID attribute to an object or paired object if missing.
 * If 2 objects are provided and at least 1 does not have a CKA_ID,
 * the 2 objects will have the same CKA_ID attribute.
 *
 * @attrs1 - Object
 * @attrs2 - Object paired to attrs1 or NULL
 * Return an PKCS11 return code
 */
enum pkcs11_rc add_missing_attribute_id(struct obj_attrs **attrs1,
					struct obj_attrs **attrs2)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	void *id1 = NULL;
	uint32_t id1_size = 0;
	void *id2 = NULL;
	uint32_t id2_size = 0;

	rc = remove_empty_attribute(attrs1, PKCS11_CKA_ID);
	if (rc)
		return rc;

	rc = get_attribute_ptr(*attrs1, PKCS11_CKA_ID, &id1, &id1_size);
	if (rc) {
		if (rc != PKCS11_RV_NOT_FOUND)
			return rc;
		id1 = NULL;
	}

	if (attrs2) {
		rc = remove_empty_attribute(attrs2, PKCS11_CKA_ID);
		if (rc)
			return rc;

		rc = get_attribute_ptr(*attrs2, PKCS11_CKA_ID, &id2, &id2_size);
		if (rc) {
			if (rc != PKCS11_RV_NOT_FOUND)
				return rc;
			id2 = NULL;
		}

		if (id1 && id2)
			return PKCS11_CKR_OK;

		if (id1 && !id2)
			return add_attribute(attrs2, PKCS11_CKA_ID,
					     id1, id1_size);

		if (!id1 && id2)
			return add_attribute(attrs1, PKCS11_CKA_ID,
					     id2, id2_size);
	} else {
		if (id1)
			return PKCS11_CKR_OK;
	}

	id1_size = PKCS11_CKA_DEFAULT_SIZE;
	id1 = TEE_Malloc(id1_size, 0);
	if (!id1)
		return PKCS11_CKR_DEVICE_MEMORY;

	TEE_GenerateRandom(id1, (uint32_t)id1_size);

	rc = add_attribute(attrs1, PKCS11_CKA_ID, id1, id1_size);
	if (rc == PKCS11_CKR_OK && attrs2)
		rc = add_attribute(attrs2, PKCS11_CKA_ID, id1, id1_size);

	TEE_Free(id1);

	return rc;
}

bool attribute_is_exportable(struct pkcs11_attribute_head *req_attr,
			     struct pkcs11_object *obj)
{
	uint8_t boolval = 0;
	uint32_t boolsize = 0;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;

	switch (req_attr->id) {
	case PKCS11_CKA_PRIVATE_EXPONENT:
	case PKCS11_CKA_PRIME_1:
	case PKCS11_CKA_PRIME_2:
	case PKCS11_CKA_EXPONENT_1:
	case PKCS11_CKA_EXPONENT_2:
	case PKCS11_CKA_COEFFICIENT:
		boolsize = sizeof(boolval);
		rc = get_attribute(obj->attributes, PKCS11_CKA_EXTRACTABLE,
				   &boolval, &boolsize);
		if (rc || boolval == PKCS11_FALSE)
			return false;

		boolsize = sizeof(boolval);
		rc = get_attribute(obj->attributes, PKCS11_CKA_SENSITIVE,
				   &boolval, &boolsize);
		if (rc || boolval == PKCS11_TRUE)
			return false;
		break;
	default:
		break;
	}

	return true;
}

bool attribute_is_settable(struct pkcs11_attribute_head *req_attr,
			   struct pkcs11_object *obj)
{
	uint8_t boolval = 0;
	uint32_t boolsize = 0;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;

	switch (req_attr->id) {
	case PKCS11_CKA_SENSITIVE:
		/* Only allow change from CK_FALSE -> CK_TRUE */
		boolsize = sizeof(boolval);
		rc = get_attribute(obj->attributes, PKCS11_CKA_SENSITIVE,
				   &boolval, &boolsize);
		if (rc || boolval == PKCS11_TRUE)
			return false;
		break;

	case PKCS11_CKA_EXTRACTABLE:
		/* Only allow change from CK_TRUE -> CK_FALSE */
		boolsize = sizeof(boolval);
		rc = get_attribute(obj->attributes, PKCS11_CKA_EXTRACTABLE,
				   &boolval, &boolsize);
		if (rc || boolval == PKCS11_FALSE)
			return false;
		break;
	default:
		break;
	}
	return true;
}
