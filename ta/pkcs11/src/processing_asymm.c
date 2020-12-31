// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018-2020, Linaro Limited
 */

#include <assert.h>
#include <compiler.h>
#include <tee_api_defines.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "attributes.h"
#include "pkcs11_token.h"
#include "processing.h"
#include "serializer.h"
#include "pkcs11_helpers.h"

bool processing_is_tee_asymm(uint32_t proc_id)
{
	switch (proc_id) {
	/* EC flavors */
	case PKCS11_CKM_ECDSA:
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
		return true;
	default:
		return false;
	}
}

static uint32_t pkcs2tee_algorithm(uint32_t *tee_id,
				   enum processing_func function,
				   struct pkcs11_attribute_head *proc_params,
				   struct pkcs11_object *obj)
{
	static const uint32_t pkcs2tee_algo[][2] = {
		/* EC flavors (Must find key size from the object) */
		{ PKCS11_CKM_ECDSA, 1 },
		{ PKCS11_CKM_ECDSA_SHA1, 1 },
		{ PKCS11_CKM_ECDSA_SHA224, 1 },
		{ PKCS11_CKM_ECDSA_SHA256, 1 },
		{ PKCS11_CKM_ECDSA_SHA384, 1 },
		{ PKCS11_CKM_ECDSA_SHA512, 1 },
	};
	size_t end = sizeof(pkcs2tee_algo) / (2 * sizeof(uint32_t));
	size_t n = 0;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;

	for (n = 0; n < end; n++) {
		if (proc_params->id == pkcs2tee_algo[n][0]) {
			*tee_id = pkcs2tee_algo[n][1];
			break;
		}
	}

	if (n == end)
		return PKCS11_RV_NOT_IMPLEMENTED;

	switch (proc_params->id) {
	case PKCS11_CKM_ECDSA:
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
		rc = pkcs2tee_algo_ecdsa(tee_id, proc_params, obj);
		break;
	default:
		rc = PKCS11_CKR_OK;
		break;
	}

	return rc;
}

static uint32_t pkcs2tee_key_type(uint32_t *tee_type, struct pkcs11_object *obj,
				  enum processing_func function)
{
	enum pkcs11_class_id class = get_class(obj->attributes);
	enum pkcs11_key_type type = get_key_type(obj->attributes);

	switch (class) {
	case PKCS11_CKO_PUBLIC_KEY:
	case PKCS11_CKO_PRIVATE_KEY:
		break;
	default:
		TEE_Panic(class);
		break;
	}

	switch (type) {
	case PKCS11_CKK_EC:
		assert(function != PKCS11_FUNCTION_DERIVE);

		if (class == PKCS11_CKO_PRIVATE_KEY)
			*tee_type = TEE_TYPE_ECDSA_KEYPAIR;
		else
			*tee_type = TEE_TYPE_ECDSA_PUBLIC_KEY;
		break;
	default:
		TEE_Panic(type);
		break;
	}

	return PKCS11_CKR_OK;
}

static uint32_t allocate_tee_operation(struct pkcs11_session *session,
				       enum processing_func function,
				       struct pkcs11_attribute_head *params,
				       struct pkcs11_object *obj)
{
	uint32_t size = (uint32_t)get_object_key_bit_size(obj);
	uint32_t algo = 0;
	uint32_t mode = 0;
	TEE_Result res = TEE_ERROR_GENERIC;

	assert(session->processing->tee_op_handle == TEE_HANDLE_NULL);

	if (pkcs2tee_algorithm(&algo, function, params, obj))
		return PKCS11_CKR_FUNCTION_FAILED;

	pkcs2tee_mode(&mode, function);

	res = TEE_AllocateOperation(&session->processing->tee_op_handle,
				    algo, mode, size);
	if (res)
		EMSG("TEE_AllocateOp. failed %#"PRIx32" %#"PRIx32" %#"PRIx32,
		     algo, mode, size);

	if (res == TEE_ERROR_NOT_SUPPORTED)
		return PKCS11_CKR_MECHANISM_INVALID;

	return tee2pkcs_error(res);
}

static uint32_t load_tee_key(struct pkcs11_session *session,
			     struct pkcs11_object *obj,
			     enum processing_func function)
{
	TEE_Attribute *tee_attrs = NULL;
	size_t tee_attrs_count = 0;
	size_t object_size = 0;
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	TEE_Result res = TEE_ERROR_GENERIC;
	enum pkcs11_class_id __maybe_unused class = get_class(obj->attributes);
	enum pkcs11_key_type type = get_key_type(obj->attributes);

	assert(class == PKCS11_CKO_PUBLIC_KEY ||
	       class == PKCS11_CKO_PRIVATE_KEY);

	if (obj->key_handle != TEE_HANDLE_NULL) {
		switch (type) {
		case PKCS11_CKK_EC:
			/* Reuse EC TEE key only if already DSA or DH */
			switch (obj->key_type) {
			case TEE_TYPE_ECDSA_PUBLIC_KEY:
			case TEE_TYPE_ECDSA_KEYPAIR:
				if (function != PKCS11_FUNCTION_DERIVE)
					goto key_ready;
				break;
			default:
				assert(0);
				break;
			}
			break;
		default:
			assert(0);
			break;
		}

		TEE_CloseObject(obj->key_handle);
		obj->key_handle = TEE_HANDLE_NULL;
	}

	rc = pkcs2tee_key_type(&obj->key_type, obj, function);
	if (rc)
		return rc;

	object_size = get_object_key_bit_size(obj);
	if (!object_size)
		return PKCS11_CKR_GENERAL_ERROR;

	switch (type) {
	case PKCS11_CKK_EC:
		rc = load_tee_ec_key_attrs(&tee_attrs, &tee_attrs_count, obj);
		break;
	default:
		break;
	}
	if (rc)
		return rc;

	res = TEE_AllocateTransientObject(obj->key_type, object_size,
					  &obj->key_handle);
	if (res) {
		DMSG("TEE_AllocateTransientObject failed, %#"PRIx32, res);

		return tee2pkcs_error(res);
	}

	res = TEE_PopulateTransientObject(obj->key_handle,
					  tee_attrs, tee_attrs_count);

	TEE_Free(tee_attrs);

	if (res) {
		DMSG("TEE_PopulateTransientObject failed, %#"PRIx32, res);

		goto error;
	}

key_ready:
	res = TEE_SetOperationKey(session->processing->tee_op_handle,
				  obj->key_handle);
	if (res) {
		DMSG("TEE_SetOperationKey failed, %#"PRIx32, res);

		goto error;
	}

	return tee2pkcs_error(res);

error:
	TEE_FreeTransientObject(obj->key_handle);
	obj->key_handle = TEE_HANDLE_NULL;
	return tee2pkcs_error(res);
}

static uint32_t
init_tee_operation(struct pkcs11_session *session __unused,
		   struct pkcs11_attribute_head *proc_params __unused)
{
	return PKCS11_CKR_OK;
}

uint32_t init_asymm_operation(struct pkcs11_session *session,
			      enum processing_func function,
			      struct pkcs11_attribute_head *proc_params,
			      struct pkcs11_object *obj)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;

	assert(processing_is_tee_asymm(proc_params->id));

	rc = allocate_tee_operation(session, function, proc_params, obj);
	if (rc)
		return rc;

	rc = load_tee_key(session, obj, function);
	if (rc)
		return rc;

	return init_tee_operation(session, proc_params);
}

/*
 * step_sym_step - step (update/oneshot/final) on a symmetric crypto operation
 *
 * @session - current session
 * @function - processing function (encrypt, decrypt, sign, ...)
 * @step - step ID in the processing (oneshot, update, final)
 * @ptype - invocation parameter types
 * @params - invocation parameter references
 */
uint32_t step_asymm_operation(struct pkcs11_session *session,
			      enum processing_func function,
			      enum processing_step step,
			      uint32_t ptypes, TEE_Param *params)
{
	enum pkcs11_rc rc = PKCS11_CKR_GENERAL_ERROR;
	TEE_Result res = TEE_ERROR_GENERIC;
	void *in_buf = NULL;
	void *in2_buf = NULL;
	void *out_buf = NULL;
	size_t in_size = 0;
	size_t in2_size = 0;
	size_t out_size = 0;
	TEE_Attribute *tee_attrs = NULL;
	size_t tee_attrs_count = 0;
	bool output_data = false;
	struct active_processing *proc = session->processing;
	size_t sz = 0;

	if (TEE_PARAM_TYPE_GET(ptypes, 1) == TEE_PARAM_TYPE_MEMREF_INPUT) {
		in_buf = params[1].memref.buffer;
		in_size = params[1].memref.size;
		if (in_size && !in_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;
	}
	if (TEE_PARAM_TYPE_GET(ptypes, 2) == TEE_PARAM_TYPE_MEMREF_INPUT) {
		in2_buf = params[2].memref.buffer;
		in2_size = params[2].memref.size;
		if (in2_size && !in2_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;
	}
	if (TEE_PARAM_TYPE_GET(ptypes, 2) == TEE_PARAM_TYPE_MEMREF_OUTPUT) {
		out_buf = params[2].memref.buffer;
		out_size = params[2].memref.size;
		if (out_size && !out_buf)
			return PKCS11_CKR_ARGUMENTS_BAD;
	}
	if (TEE_PARAM_TYPE_GET(ptypes, 3) != TEE_PARAM_TYPE_NONE)
		return PKCS11_CKR_ARGUMENTS_BAD;

	switch (step) {
	case PKCS11_FUNC_STEP_ONESHOT:
	case PKCS11_FUNC_STEP_UPDATE:
	case PKCS11_FUNC_STEP_FINAL:
		break;
	default:
		return PKCS11_CKR_GENERAL_ERROR;
	}

	/* TEE attribute(s) required by the operation */
	switch (proc->mecha_type) {
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
		if (step == PKCS11_FUNC_STEP_FINAL)
			break;

		EMSG("TODO: compute hash for later authentication");
		rc = PKCS11_RV_NOT_IMPLEMENTED;
		goto out;
	default:
		/* Other mechanism do not expect multi stage operation */
		rc = PKCS11_CKR_GENERAL_ERROR;
		break;
	}

	if (step == PKCS11_FUNC_STEP_UPDATE)
		goto out;

	/*
	 * Finalize
	 */

	/* These ECDSA need to use the computed hash as input data */
	switch (proc->mecha_type) {
	case PKCS11_CKM_ECDSA:
		sz = ecdsa_get_input_max_byte_size(proc->tee_op_handle);
		if (!in_size || !sz) {
			rc = PKCS11_CKR_FUNCTION_FAILED;
			goto out;
		}
		/*
		 * Limit input size upon key size
		 * TODO: confirm it is ok to discard some input bytes
		 * Would expect in_size > sz should return a failure
		 */
		if (in_size > sz)
			in_size = sz;

		if (function == PKCS11_FUNCTION_VERIFY &&
		    in2_size != 2 * sz) {
			rc = PKCS11_CKR_SIGNATURE_LEN_RANGE;
			goto out;
		}
		break;
	case PKCS11_CKM_ECDSA_SHA1:
		in_buf = proc->extra_ctx;
		in_size = 192;
		break;
	case PKCS11_CKM_ECDSA_SHA224:
		in_buf = proc->extra_ctx;
		in_size = 224;
		break;
	case PKCS11_CKM_ECDSA_SHA256:
		in_buf = proc->extra_ctx;
		in_size = 256;
		break;
	case PKCS11_CKM_ECDSA_SHA384:
		in_buf = proc->extra_ctx;
		in_size = 384;
		break;
	case PKCS11_CKM_ECDSA_SHA512:
		in_buf = proc->extra_ctx;
		in_size = 512;
		break;
	default:
		if (step != PKCS11_FUNC_STEP_ONESHOT) {
			rc = PKCS11_CKR_GENERAL_ERROR;
			goto out;
		}
		break;
	}

	switch (proc->mecha_type) {
	case PKCS11_CKM_ECDSA:
	case PKCS11_CKM_ECDSA_SHA1:
	case PKCS11_CKM_ECDSA_SHA224:
	case PKCS11_CKM_ECDSA_SHA256:
	case PKCS11_CKM_ECDSA_SHA384:
	case PKCS11_CKM_ECDSA_SHA512:
		switch (function) {
		case PKCS11_FUNCTION_ENCRYPT:
			// TODO: TEE_ALG_RSAES_PKCS1_OAEP_MGF1_xxx takes an
			// optional argument TEE_ATTR_RSA_OAEP_LABEL.
			res = TEE_AsymmetricEncrypt(proc->tee_op_handle,
						    tee_attrs, tee_attrs_count,
						    in_buf, in_size,
						    out_buf, &out_size);
			output_data = true;
			rc = tee2pkcs_error(res);
			break;

		case PKCS11_FUNCTION_DECRYPT:
			res = TEE_AsymmetricDecrypt(proc->tee_op_handle,
						    tee_attrs, tee_attrs_count,
						    in_buf, in_size,
						    out_buf, &out_size);
			output_data = true;
			rc = tee2pkcs_error(res);
			break;

		case PKCS11_FUNCTION_SIGN:
			res = TEE_AsymmetricSignDigest(proc->tee_op_handle,
						       tee_attrs,
						       tee_attrs_count,
						       in_buf, in_size,
						       out_buf, &out_size);
			output_data = true;
			rc = tee2pkcs_error(res);
			break;

		case PKCS11_FUNCTION_VERIFY:
			res = TEE_AsymmetricVerifyDigest(proc->tee_op_handle,
							 tee_attrs,
							 tee_attrs_count,
							 in_buf, in_size,
							 in2_buf, in2_size);
			rc = tee2pkcs_error(res);
			break;

		default:
			TEE_Panic(function);
			break;
		}
		break;
	default:
		TEE_Panic(proc->mecha_type);
		break;
	}
out:
	if (output_data &&
	    (rc == PKCS11_CKR_OK || rc == PKCS11_CKR_BUFFER_TOO_SMALL)) {
		switch (TEE_PARAM_TYPE_GET(ptypes, 2)) {
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			params[2].memref.size = out_size;
			break;
		default:
			rc = PKCS11_CKR_GENERAL_ERROR;
			break;
		}
	}

	TEE_Free(tee_attrs);

	return rc;
}
