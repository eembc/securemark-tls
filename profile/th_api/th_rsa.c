
#include "ee_main.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

ee_status_t
th_rsa_create(void **pp_context) {
#warning "th_rsa_create not implemented"
}

ee_status_t th_rsa_init(void *p_context, uint8_t *prikey, uint8_t *pubkey) {
#warning "ths_rsa_init not implemented"
}

ee_status_t th_rsa_sign(void *         p_context,
                        uint8_t *      p_msg,
                        uint_fast32_t  mlen,
                        uint8_t *      p_sig,
                        uint_fast32_t *p_slen) {
#warning "th_rsa_sign not implemented"
}

ee_status_t th_rsa_verify(void *        p_context,
                          uint8_t *     p_msg,
                          uint_fast32_t mlen,
                          uint8_t *     p_sig,
                          uint_fast32_t slen,
                          uint8_t *     p_verify) {
#warning "th_rsa_sign not implemented"
}

ee_status_t th_rsa_destroy(void *p_context)
{
#warning "th_rsa_destroy not implemented"
}