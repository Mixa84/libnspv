
#define FOREACH_EVAL(EVAL)             \
        EVAL(EVAL_ORACLESV2, 0xe0) \
        EVAL(EVAL_IMPORTPAYOUT, 0xe1)  \
        EVAL(EVAL_IMPORTCOIN, 0xe2)  \
        EVAL(EVAL_ASSETS, 0xe3)  \
        EVAL(EVAL_FAUCET, 0xe4) \
        EVAL(EVAL_REWARDS, 0xe5) \
        EVAL(EVAL_DICE, 0xe6) \
        EVAL(EVAL_FSM, 0xe7) \
        EVAL(EVAL_AUCTION, 0xe8) \
        EVAL(EVAL_LOTTO, 0xe9) \
        EVAL(EVAL_HEIR, 0xea) \
        EVAL(EVAL_CHANNELS, 0xeb) \
        EVAL(EVAL_ORACLES, 0xec) \
        EVAL(EVAL_PRICES, 0xed) \
        EVAL(EVAL_PEGS, 0xee) \
        EVAL(EVAL_MARMARA, 0xef) \
        EVAL(EVAL_PAYMENTS, 0xf0) \
        EVAL(EVAL_GATEWAYS, 0xf1) \
		EVAL(EVAL_TOKENS, 0xf2) \
        EVAL(EVAL_IMPORTGATEWAY, 0xf3)  \
        EVAL(EVAL_KOGS, 0xf4)  \
        EVAL(EVAL_TOKENSV2, 0xf5) \


#define EVAL_GENERATE_DEF(L,I) const uint8_t L = I;
#define EVAL_GENERATE_STRING(L,I) if (c == I) return #L;

FOREACH_EVAL(EVAL_GENERATE_DEF)

int64_t NSPV_AddNormalinputs(btc_spv_client *client,btc_tx *mtx,int64_t total,int32_t maxinputs,struct NSPV_CCmtxinfo *ptr);
btc_tx* NSPV_gettx(btc_spv_client* client, bits256 txid, int32_t v, int32_t height);

#include "../nSPV_CCUtils.h"
#include "nSPV_defs.h"
#include "../nSPV_CCtx.h"



#include "channels.h"
