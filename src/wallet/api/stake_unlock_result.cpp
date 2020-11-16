#include "stake_unlock_result.h"

namespace Wallet {

StakeUnlockResult::~StakeUnlockResult() {}

//StakeUnlockResultImpl::StakeUnlockResultImpl(tools::wallet2::request_stake_unlock_result& result)
//{

    //success = result.success;
    //msg = result.msg;
    //ptx = &result.ptx;

//}

StakeUnlockResultImpl::StakeUnlockResultImpl()
{
}

StakeUnlockResultImpl::~StakeUnlockResultImpl()
{
    LOG_PRINT_L3("Stake Unlock Result Deleted");
}

} // namespace
