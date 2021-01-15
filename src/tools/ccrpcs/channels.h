#ifndef CC_MARKER_VALUE
    #define CC_MARKER_VALUE 10000
#endif
#ifndef CHANNELCC_VERSION
    #define CHANNELCC_VERSION 1
#endif
#ifndef CC_TXFEE
    #define CC_TXFEE 10000
#endif

#define CHANNELS_MAXPAYMENTS 1000

cJSON* channelsopen(btc_spv_client *client,btc_pubkey *destpub,int32_t numpayments,int64_t payment,uint16_t confirmation,bits256 tokenid)
{
    btc_tx *mtx; char str[128]; struct CCcontract_info *cp,C; int64_t funds,tokens=0,amount; int32_t i;
    struct NSPV_CCmtxinfo txinfo; btc_tx_in *v0; bits256 hentropy,vouthash; uint8_t hash[32],hashdest[32];

    if ( numpayments <= 0 || payment <= 0 || numpayments > CHANNELS_MAXPAYMENTS )
    {
        sprintf(str,"invalid channelsopen param numpayments.%d payment.%ld - max_numpayments.%d",numpayments,payment,CHANNELS_MAXPAYMENTS);
        ccerror("channelscc",str);
    }
    if (!btc_pubkey_is_valid(destpub))
        ccerror("channelscc","invalid destination pubkey");
    if (numpayments <1)
        ccerror("channelscc","invalid number of payments, must be greater than 0");
    if (payment <1)
        ccerror("channelscc","invalid payment amount, must be greater than 0");
    cp = CCinit(&C,EVAL_CHANNELS);
    //cpTokens = CCinit(&CTokens,EVAL_TOKENSV2);
    funds = numpayments * payment;
    mtx=btc_tx_new(SAPLING_TX_VERSION);
    //if (memcmp(&tokenid,&zeroid,32)!=0)
    {
        //tokens=AddTokenCCInputs<V2>(cpTokens, mtx, mypk, tokenid, funds, 64, false);   
        //CC* cond(V2::MakeTokensCCcond1(cpTokens->evalcode,mypk));
        //CCAddVintxCond(cp,cond); 
        //amount=AddNormalinputs(mtx,mypk,txfee+2*CC_MARKER_VALUE,5,pk.IsValid());
    }
    amount=NSPV_AddNormalinputs(client,mtx,funds+CC_TXFEE+2*CC_MARKER_VALUE,64,&txinfo);
    if (amount >= funds+CC_TXFEE+2*CC_MARKER_VALUE)
    {
        v0=btc_tx_vin(mtx,0);
        vouthash=btc_uint256_to_bits256(v0->prevout.hash);
        hentropy = HashEntropy(vouthash,v0->prevout.n,1);
        endiancpy(hash,(uint8_t *)&hentropy,32);
        for (i=0; i<numpayments; i++)
        {
            vcalc_sha256(0,hashdest,hash,32);
            memcpy(hash,hashdest,32);
        }
        endiancpy((uint8_t *)&hentropy,hashdest,32);

        vector_add(mtx->vout,MakeCC1of2vout(EVAL_CHANNELS,funds,NSPV_pubkey.pubkey,destpub->pubkey,true));
        vector_add(mtx->vout,MakeCC1vout(EVAL_CHANNELS,CC_MARKER_VALUE,NSPV_pubkey.pubkey,true));
        vector_add(mtx->vout,MakeCC1vout(EVAL_CHANNELS,CC_MARKER_VALUE,destpub->pubkey,true));
        return (NULL);
        //return(FinalizeCCV2Tx(pk.IsValid(),0,cp,mtx,NSPV_pubkey.pubkey,CC_TXFEE,EncodeChannelsOpRet('O',tokenid,zeroid,mypk,destpub,numpayments,payment,hashchain,CHANNELCC_VERSION,confirmation)));
    }
}
