// Copyright (c) 2018-2020, The Gyuanx Project
// Copyright (c) 2014-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once
#include <cstdint>

namespace cryptonote { namespace rpc {

constexpr int16_t
    ERROR_WRONG_PARAM           = -1,
    ERROR_TOO_BIG_HEIGHT        = -2,
    ERROR_TOO_BIG_RESERVE_SIZE  = -3,
    ERROR_WRONG_WALLET_ADDRESS  = -4,
    ERROR_INTERNAL              = -5,
    ERROR_WRONG_BLOCKBLOB       = -6,
    ERROR_BLOCK_NOT_ACCEPTED    = -7,
    ERROR_CORE_BUSY             = -9,
    ERROR_WRONG_BLOCKBLOB_SIZE  = -10,
    ERROR_UNSUPPORTED_RPC       = -11,
    ERROR_MINING_TO_SUBADDRESS  = -12,
    ERROR_REGTEST_REQUIRED      = -13;

}}
