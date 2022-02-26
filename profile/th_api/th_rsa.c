
#include "ee_main.h"
#include "th_lib.h"
#include "th_libc.h"
#include "th_util.h"

ee_status_t
th_rsa_create(void **pp_context // output: portable context
) {
#warning "th_rsa_create not implemented"
}

ee_status_t th_rsa_init(
    void *   p_context, // input: portable context
    uint8_t *prikey,    // input: private key in ANS.1/DER PKS1v1.5 format ???
    // should include the public key/ because if we force them to generate it
    // during the timing loop that's a big cost. TODO
    uint8_t *pubkey // input: public key associated with private
) {
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