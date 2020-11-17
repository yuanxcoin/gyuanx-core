#include "wallet/api/wallet2_api.h"
#include "wallet/wallet2.h"

#include <string>


namespace Wallet {

class WalletImpl;
class StakeUnlockResultImpl : public StakeUnlockResult
{
public:
    StakeUnlockResultImpl(tools::wallet2::request_stake_unlock_result res);
    StakeUnlockResultImpl();
    ~StakeUnlockResultImpl();

    bool success();
    std::string msg();
    PendingTransaction * ptx();

private:
    tools::wallet2::request_stake_unlock_result &result;
};


}
