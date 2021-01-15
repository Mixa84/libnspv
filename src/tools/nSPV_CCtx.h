
/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#ifndef NSPV_CCTX_H
#define NSPV_CCTX_H

#include "nSPV_defs.h"
#include "nSPV_CCUtils.h"
// @blackjok3r and @mihailo implement the CC tx creation functions here
// instead of a swissarmy knife finalizeCCtx, i think it is better to pass in the specific info needed into a CC signing function. this would eliminate the comparing to all the different possibilities
// since the CC rpc that creates the tx will know which vins are normal and which ones are CC, and most importantly what type of CC vin it is, it will be much simpler finalize function, though it will mean all the CC rpc calls will have to do more work. that was the rationale behind FinalizeCCtx, but i hear a lot of complaints about the complexity it has become.
// please make a new way of doing CC tx that wont lead to complaints later. let us start with faucetget

cJSON* FinalizeCCtx(uint64_t mask,struct CCcontract_info *cp, btc_tx *mtx, btc_pubkey *mypk, uint64_t txfee, cstring *opret)
{
    btc_tx *vintx; int32_t n,i,utxovout; uint64_t totaloutputs=0,totalinputs=0,utxovalues[CC_MAXVINS],change;
    char err[512],str[64],destaddr[64];

    n = mtx->vout->len;
    for (i=0; i<n; i++)
    {
        btc_tx_out *tmp=btc_tx_vout(mtx,i);
        totaloutputs += tmp->value;
    }
    if ( (n=mtx->vin->len) > CC_MAXVINS )
    {
        sprintf(err,"FinalizeCCV2Tx: %d is too many vins",n);
        fprintf(stderr,"%s\n",err);
        return (ccerror("FinalizeCCtx",err));
    }
    memset(utxovalues,0,sizeof(utxovalues));
    for (i=0; i<n; i++)
    {
        btc_tx_in *tmpin=btc_tx_vin(mtx,i);
        utxovout = tmpin->prevout.n;
        if (i==0 && utxovout==10e8) continue;
        if ( (vintx=NSPV_gettx(NSPV_client,btc_uint256_to_bits256(tmpin->prevout.hash),utxovout,0))!=NULL)
        {
            
            btc_tx_out *tmpout=btc_tx_vout(vintx,utxovout);
            utxovalues[i] = tmpout->value;
            totalinputs += utxovalues[i];
        } else fprintf(stderr,"FinalizeCCV2Tx couldnt find %s\n",bits256_str(str,btc_uint256_to_bits256(tmpin->prevout.hash)));
    }
    if ( !(mask & FINALIZECCTX_NO_CHANGE) && (totalinputs >= totaloutputs+txfee) )
    {
        change = totalinputs - (totaloutputs+txfee);
        if (!(mask & FINALIZECCTX_NO_CHANGE_WHEN_ZERO) || change>0 ) btc_tx_add_p2pk(mtx,change,mypk->pubkey);
    }
    if ( opret->len > 0 )
        btc_tx_add_txout(mtx,0,opret);
    n = mtx->vin->len;
    for (i=0; i<n; i++)
    {
        btc_tx_in *tmpin=btc_tx_vin(mtx,i);;
        if (i==0 && tmpin->prevout.n==10e8) continue;
        if ( (vintx=NSPV_gettx(NSPV_client,btc_uint256_to_bits256(tmpin->prevout.hash),tmpin->prevout.n,0))!=NULL)
        {
            btc_tx_out *vout=btc_tx_vout(mtx,tmpin->prevout.n);
            if ( IsPayToCryptoCondition(vout->script_pubkey,true) == 0 )
            {
                if (NSPV_SignTx(mtx, i, vout->value, vout->script_pubkey, 0) == 0)
                {
                    sprintf(err,"signing error for vini.%d\n", i);     
                    nspv_log_message(err);
                    return (ccerror("FinalizeCCtx",err));
                    cstr_free(vout->script_pubkey, 1);
                    btc_tx_free(mtx);
                    return NULL;
                }
            }
            else
            {
                Getscriptaddress(destaddr,vout->script_pubkey->str);
                
            }
            
        }
    }
}

cstring* FinalizeCCtxRemote(/*btc_spv_client* client,*/ cJSON* txdata, char* errorout)
{
    int32_t i, n, vini;
    cstring *finalHex, *hex;
    cJSON* sigData = NULL;
    int64_t voutValue;

    if (errorout)
        errorout[0] = '\0';

    if (!cJSON_HasObjectItem(txdata, "hex")) {
        nspv_log_message("%s No field \"hex\" in JSON response from fullnode\n", __func__);
        return NULL;
    }

    hex = cstr_new(jstr(txdata, "hex"));
    cstr_append_c(hex, 0);
    btc_tx* mtx = btc_tx_decodehex(hex->str);

    cstr_free(hex, 1);

    if (!mtx) {
        nspv_log_message("%s Invalid hex tx in JSON response from fullnode (could not parse into mtx)\n", __func__);
        if (errorout) {
            snprintf(errorout, NSPV_MAXERRORLEN - 1, "Invalid hex tx in txdata parameter");
            errorout[NSPV_MAXERRORLEN - 1] = '\0';
        }
        //return(cstr_new("Invalid hex in JSON response from fullnode"));
        return NULL;
    }
    sigData = jarray(&n, txdata, "SigData");

    if (!sigData) {
        nspv_log_message("%s No field \"SigData\" in JSON response from fullnode\n", __func__);
        if (errorout) {
            snprintf(errorout, NSPV_MAXERRORLEN - 1, "No field \"SigData\" in txdata parameter");
            errorout[NSPV_MAXERRORLEN - 1] = '\0';
        }
        btc_tx_free(mtx);
        return NULL;
    }
    for (i = 0; i < n; i++) {

        cJSON* item = jitem(sigData, i);
        vini = jint(item, "vin");
        voutValue = j64bits(item, "amount");
        if (cJSON_HasObjectItem(item, "cc") != 0) {
            CC* cond;
            btc_tx_in* vin = btc_tx_vin(mtx, vini);
            bits256 sigHash;
            char ccerror[256] = {'\0'};

            cond = cc_conditionFromJSON(jobj(item, "cc"), ccerror);
            if (cond == NULL) {
                btc_tx_free(mtx);
                nspv_log_message("%s cc error from cc_conditionFromJSON %s\n", __func__, ccerror);
                if (errorout) {
                    snprintf(errorout, NSPV_MAXERRORLEN - 1, "error from parse \"cc\" field %s", ccerror);
                    errorout[NSPV_MAXERRORLEN - 1] = '\0';
                }
                return NULL;
            }
            cstring* script = CCPubKey(cond,false);

            uint8_t privkey[32];
            if (cJSON_HasObjectItem(item, "globalPrivKey") != 0) {
                // use global privkey from the komodod
                char* privhex = jstr(item, "globalPrivKey");
                int privhexlen = (int)strlen(privhex);
                int outlen;

                if (privhexlen / 2 > (int)sizeof(privkey))
                    privhexlen = (int)sizeof(privkey) * 2;
                utils_hex_to_bin(privhex, privkey, privhexlen, &outlen);
            } else {
                memcpy(privkey, NSPV_key.privkey, sizeof(privkey));
            }
            sigHash = NSPV_sapling_sighash(mtx, vini, voutValue, (unsigned char*)script->str, script->len);
            sigHash = bits256_rev(sigHash);
            if ((cc_signTreeSecp256k1Msg32(cond, privkey, sigHash.bytes)) != 0) {
                if (vin->script_sig) {
                    cstr_free(vin->script_sig, 1);
                    vin->script_sig = cstr_new("");
                }
                CCSig(cond, vin->script_sig);
            } 

            cstr_free(script, 1);
            cc_free(cond);

            memset(privkey, '\0', sizeof(privkey));
        } else {
            cstring* voutScriptPubkey = cstr_new((char*)utils_hex_to_uint8(jstr(item, "scriptPubKey")));
            if (NSPV_SignTx(mtx, vini, voutValue, voutScriptPubkey, 0) == 0) {
                nspv_log_message("signing error for vini.%d\n", vini);
                if (errorout) {
                    snprintf(errorout, NSPV_MAXERRORLEN - 1, "signing error for vini.%d", vini);
                    errorout[NSPV_MAXERRORLEN - 1] = '\0';
                }
                cstr_free(voutScriptPubkey, 1);
                btc_tx_free(mtx);
                return NULL;
            }
            cstr_free(voutScriptPubkey, 1);
        }
    }
    finalHex = btc_tx_to_cstr(mtx);
    //nspv_log_message("%s returning signed hex tx\n", __func__);

    btc_tx_free(mtx);
    return (finalHex);
}
#endif // NSPV_CCTX_H
