#include <sodium.h>

#include <erl_nif.h>

#include "enacl.h"
#include "kdf.h"
#include <string.h>

ERL_NIF_TERM enacl_crypto_kdf_keygen(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]) {
  unsigned req_size;
  ErlNifBinary result;

  if ((argc != 1) || (!enif_get_uint(env, argv[0], &req_size))) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(req_size, &result)) {
    return enacl_internal_error(env);
  }

  randombytes(result.data, result.size);

  return enif_make_binary(env, &result);
}

ERL_NIF_TERM enacl_crypto_kdf_derive_from_key(ErlNifEnv *env, int argc,
                                     ERL_NIF_TERM const argv[]) {
  ErlNifBinary ski, c, mk, sk;
  unsigned req_size;

  unsigned char keyid[crypto_generichash_blake2b_SALTBYTES] = {0};
  unsigned char appid[crypto_generichash_blake2b_PERSONALBYTES] = {0};

  if ((argc != 4) || (!enif_inspect_binary(env, argv[0], &ski)) ||
      (!enif_get_uint(env, argv[1], &req_size)) ||
      (!enif_inspect_binary(env, argv[2], &c)) ||
      (!enif_inspect_binary(env, argv[3], &mk))) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(req_size, &sk)) {
    return enacl_internal_error(env);
  }

  strncpy(&keyid, ski.data,
          ski.size < crypto_generichash_blake2b_SALTBYTES ? ski.size : crypto_generichash_blake2b_SALTBYTES);
  strncpy(&appid, c.data,
          c.size < crypto_generichash_blake2b_PERSONALBYTES ? c.size : crypto_generichash_blake2b_PERSONALBYTES);

  if (0 != crypto_generichash_blake2b_salt_personal(sk.data, sk.size,
                                                    NULL, 0,
                                                    mk.data, mk.size,
                                                    keyid, appid)) {
    enif_release_binary(&sk);
    return enacl_internal_error(env);
  }

  return enif_make_binary(env, &sk);
}
