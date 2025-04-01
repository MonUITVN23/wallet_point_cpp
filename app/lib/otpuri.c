#include "otpuri.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

/*
	Encodes all given data into url-safe data. Null-terminates
	  returned string. Caller must free the returned pointer.
	  Will treat embedded \0's as valid characters.

	length is the length in bytes of input string data
	data is the optionally null-terminated string to encode

	Returns
		Pointer to malloc'd url-safe data string
		error, 0
*/
COTPRESULT otpuri_encode_url(const char* data, size_t length, char* output)
{
	if (data == NULL || output == NULL)
		return OTP_ERROR;

	static const char to_test[] = "\"<>#%@{}|\\^~[]` ?&";

	size_t output_i = 0;
	for (size_t i = 0; i < length; i++)
	{
		output[output_i] = data[i];
		if (data[i] < 0x20 || data[i] >= 0x7F)
		{
			output_i += snprintf(output + output_i, 3 + 1, "%%%.2X", data[i]);
			output_i--;
		}
		else
		{
			for (size_t j = 0; j < 18; j++)
			{
				if (to_test[j] == data[i])
				{
					output_i += snprintf(output + output_i, 3 + 1, "%%%.2X", data[i]);
					output_i--;
					break;
				}
			}
		}
		output_i++;
	}

	return OTP_OK;
}

/*
	Returns the maximum expected length of an array needed to fill a buffer
	  with an otpuri not including the null-termination.
	
	Returns
			Length in bytes of an array to match an otpuri generation
*/
size_t otpuri_strlen(OTPData* data, const char* issuer, const char* name, const char* digest)
{
	return strlen(issuer) * 2 * 3
		+ strlen(name) * 3
		+ strlen(data->base32_secret) * 3
		+ strlen(digest) * 3
		+ 100;
}

/*
	Builds a valid, url-safe URI which is used for applications such as QR codes.
	
	issuer is the null-terminated string of the company name
	name is the null-terminated string of the username
	digest is the null-terminated string of the HMAC encryption algorithm
	output is the zero'd destination the function writes the URI to
	
	Returns
			1 on success
		error, 0
		
*/
COTPRESULT otpuri_build_uri(OTPData* data, const char* issuer, const char* name, const char* digest, char* output, size_t max_size)
{
	if (issuer == NULL || name == NULL || digest == NULL || output == NULL)
		return OTP_ERROR;

	snprintf(output, max_size, "otpuri://");
	switch (data->method)
	{
	case TOTP:
		snprintf(output + strlen(output), max_size - strlen(output), "totp");
		break;
	case HOTP:
		snprintf(output + strlen(output), max_size - strlen(output), "hotp");
		break;
	default:
		snprintf(output + strlen(output), max_size - strlen(output), "otp");
		break;
	}

	snprintf(output + strlen(output), max_size - strlen(output), "/");

	size_t issuer_len = issuer ? strlen(issuer) : 0;
	char* cissuer = (char*)malloc(issuer_len * 3 + 1);
	if (!cissuer) return OTP_ERROR;
	memset(cissuer, 0, issuer_len * 3 + 1);
	otpuri_encode_url(issuer, issuer_len, cissuer);
	snprintf(output + strlen(output), max_size - strlen(output), "%s", cissuer);

	size_t name_len = name ? strlen(name) : 0;
	char* cname = (char*)malloc(name_len * 3 + 1);
	if (!cname) {
		free(cissuer);
		return OTP_ERROR;
	}
	memset(cname, 0, name_len * 3 + 1);
	otpuri_encode_url(name, name_len, cname);
	snprintf(output + strlen(output), max_size - strlen(output), "%s", cname);

	size_t secret_len = data->base32_secret ? strlen(data->base32_secret) : 0;
	char* csecret = (char*)malloc(secret_len * 3 + 1);
	if (!csecret) {
		free(cissuer);
		free(cname);
		return OTP_ERROR;
	}
	memset(csecret, 0, secret_len * 3 + 1);
	otpuri_encode_url(data->base32_secret, secret_len, csecret);
	snprintf(output + strlen(output), max_size - strlen(output), "%s", csecret);

	size_t digest_len = digest ? strlen(digest) : 0;
	char* cdigest = (char*)malloc(digest_len * 3 + 1);
	if (!cdigest) {
		free(cissuer);
		free(cname);
		free(csecret);
		return OTP_ERROR;
	}
	memset(cdigest, 0, digest_len * 3 + 1);
	otpuri_encode_url(digest, digest_len, cdigest);
	snprintf(output + strlen(output), max_size - strlen(output), "%s", cdigest);

	free(cissuer);
	free(cname);
	free(csecret);
	free(cdigest);

	switch (data->method)
	{
	case TOTP:
		snprintf(output + strlen(output), max_size - strlen(output), "&period=%" PRIu32, data->interval);
		break;
	case HOTP:
		snprintf(output + strlen(output), max_size - strlen(output), "&counter=%" PRIu64, data->count);
		break;
	default:
		break;
	}

	return OTP_OK;
}