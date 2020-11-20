#include "stake_unlock_result.h"

namespace Wallet {

StakeUnlockResult::~StakeUnlockResult() {}

StakeUnlockResultImpl::StakeUnlockResultImpl(tools::wallet2::request_stake_unlock_result res)
    : result(std::move(res))
{
}

StakeUnlockResultImpl::~StakeUnlockResultImpl()
{
    LOG_PRINT_L3("Stake Unlock Result Deleted");
}

//----------------------------------------------------------------------------------------------------
bool StakeUnlockResultImpl::success()
{
    return result.success;
}

//----------------------------------------------------------------------------------------------------
std::string StakeUnlockResultImpl::msg()
{
    return result.msg;
}

//----------------------------------------------------------------------------------------------------
std::string StakeUnlockResultImpl::msg()
PendingTransaction* StakeUnlockResultImpl:: ptx();
{
    return &result.ptx;
}

} // namespace
