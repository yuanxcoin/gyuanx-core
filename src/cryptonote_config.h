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

#include <stdexcept>
#include <string>
#include <string_view>
#include <boost/uuid/uuid.hpp>
#include <stdexcept>
#include <chrono>
#include <array>
#include <ratio>

using namespace std::literals;

#define CRYPTONOTE_MAX_BLOCK_NUMBER                     500000000
#define CRYPTONOTE_MAX_TX_SIZE                          1000000
#define CRYPTONOTE_MAX_TX_PER_BLOCK                     0x10000000
#define CRYPTONOTE_PUBLIC_ADDRESS_TEXTBLOB_VER          0
#define CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW            60
#define CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT_V2           60*10
#define CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE             10
#define CRYPTONOTE_DEFAULT_TX_MIXIN                     9

#define STAKING_REQUIREMENT_LOCK_BLOCKS_EXCESS          20
#define STAKING_PORTIONS                                UINT64_C(0xfffffffffffffffc)
#define MAX_NUMBER_OF_CONTRIBUTORS                      4
#define MIN_PORTIONS                                    (STAKING_PORTIONS / MAX_NUMBER_OF_CONTRIBUTORS)

static_assert(STAKING_PORTIONS % 12 == 0, "Use a multiple of twelve, so that it divides evenly by two, three, or four contributors.");

#define STAKING_AUTHORIZATION_EXPIRATION_WINDOW         (60*60*24*7*2)  // 2 weeks

#define BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW               11

// For local testnet debug purposes allow shrinking the uptime proof frequency
#ifndef UPTIME_PROOF_BASE_MINUTE
#define UPTIME_PROOF_BASE_MINUTE                        60
#endif

#define UPTIME_PROOF_BUFFER_IN_SECONDS                  (5*60) // The acceptable window of time to accept a peer's uptime proof from its reported timestamp
#define UPTIME_PROOF_INITIAL_DELAY_SECONDS              (2*UPTIME_PROOF_BASE_MINUTE) // Delay after startup before sending a proof (to allow connections to be established)
#define UPTIME_PROOF_TIMER_SECONDS                      (5*UPTIME_PROOF_BASE_MINUTE) // How often we check whether we need to send an uptime proof
#define UPTIME_PROOF_FREQUENCY_IN_SECONDS               (60*UPTIME_PROOF_BASE_MINUTE) // How often we resend uptime proofs normally (i.e. after we've seen an uptime proof reply from the network)
#define UPTIME_PROOF_MAX_TIME_IN_SECONDS                (UPTIME_PROOF_FREQUENCY_IN_SECONDS * 2 + UPTIME_PROOF_BUFFER_IN_SECONDS) // How long until proofs of other network service nodes are considered expired

#define STORAGE_SERVER_PING_LIFETIME                    UPTIME_PROOF_FREQUENCY_IN_SECONDS
#define GYUANXNET_PING_LIFETIME                           UPTIME_PROOF_FREQUENCY_IN_SECONDS

#define CRYPTONOTE_REWARD_BLOCKS_WINDOW                 100
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1    20000 // NOTE(gyuanx): For testing suite, //size of block (bytes) after which reward for block calculated using block size - before first fork
#define CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5    300000 //size of block (bytes) after which reward for block calculated using block size - second change, from v5
#define CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE   100000 // size in blocks of the long term block weight median window
#define CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR 50
#define CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE          600
#define CRYPTONOTE_DISPLAY_DECIMAL_POINT                12

#define FEE_PER_KB                                      ((uint64_t)2000000000000) // 2 GYUANX (= 2 * pow(10, 9))
#define FEE_PER_BYTE                                    ((uint64_t)215)   // Fallback used in wallet if no fee is available from RPC
#define FEE_PER_BYTE_V12                                ((uint64_t)17200) // Higher fee (and fallback) in v12 (only, v13 switches back)
#define FEE_PER_OUTPUT                                  ((uint64_t)20000000) // 0.02 GYUANX per tx output (in addition to the per-byte fee), starting in v13
#define DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD            ((uint64_t)10000000000000) // 10 * pow(10,12)
#define DYNAMIC_FEE_PER_KB_BASE_FEE_V5                  ((uint64_t)400000000)
#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT        ((uint64_t)3000)
#define DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT_V12    ((uint64_t)240000) // Only v12 (v13 switches back)

// GYUANX
#pragma once
#include <cstdint>

constexpr uint64_t COIN                       = (uint64_t)1000000000; // 1 GYUANX = pow(10, 9)
constexpr uint64_t MONEY_SUPPLY               = ((uint64_t)(-1)); // MONEY_SUPPLY - total number coins to be generated
constexpr uint64_t EMISSION_LINEAR_BASE       = ((uint64_t)(1) << 58);
constexpr uint64_t EMISSION_SUPPLY_MULTIPLIER = 19;
constexpr uint64_t EMISSION_SUPPLY_DIVISOR    = 10;
constexpr uint64_t EMISSION_DIVISOR           = 2000000;

// HF15 money supply parameters:
constexpr uint64_t BLOCK_REWARD_HF15      = 25 * COIN;
constexpr uint64_t MINER_REWARD_HF15      = BLOCK_REWARD_HF15 * 24 / 100; // Only until HF16
constexpr uint64_t SN_REWARD_HF15         = BLOCK_REWARD_HF15 * 66 / 100;
constexpr uint64_t FOUNDATION_REWARD_HF15 = BLOCK_REWARD_HF15 * 10 / 100;

// HF16+ money supply parameters: same as HF15 except the miner fee goes away and is redirected to
// LF to be used exclusively for Gyuanx Chainflip liquidity seeding and incentives.  See
// https://github.com/yuanxcoin/gyuanx-improvement-proposals/issues/24 for more details.  This ends
// after 6 months.
constexpr uint64_t BLOCK_REWARD_HF16        = BLOCK_REWARD_HF15;
constexpr uint64_t CHAINFLIP_LIQUIDITY_HF16 = BLOCK_REWARD_HF15 * 24 / 100;

// HF17: at most 6 months after HF16.  This is tentative and will likely be replaced before the
// actual HF with a new reward schedule including Chainflip rewards, but as per the LRC linked
// above, the liquidity funds end after 6 months.  That means that until HF17 is finalized, this is
// the fallback if we hit the 6-months-after-HF16 point:
constexpr uint64_t BLOCK_REWARD_HF17      = 18'333'333'333;
constexpr uint64_t FOUNDATION_REWARD_HF17 =  1'833'333'333;

static_assert(MINER_REWARD_HF15        + SN_REWARD_HF15 + FOUNDATION_REWARD_HF15 == BLOCK_REWARD_HF15);
static_assert(CHAINFLIP_LIQUIDITY_HF16 + SN_REWARD_HF15 + FOUNDATION_REWARD_HF15 == BLOCK_REWARD_HF16);
static_assert(                           SN_REWARD_HF15 + FOUNDATION_REWARD_HF17 == BLOCK_REWARD_HF17);

// -------------------------------------------------------------------------------------------------
//
// Blink
//
// -------------------------------------------------------------------------------------------------
// Blink fees: in total the sender must pay (MINER_TX_FEE_PERCENT + BURN_TX_FEE_PERCENT) * [minimum tx fee] + BLINK_BURN_FIXED,
// and the miner including the tx includes MINER_TX_FEE_PERCENT * [minimum tx fee]; the rest must be left unclaimed.
constexpr uint64_t BLINK_MINER_TX_FEE_PERCENT = 100; // The blink miner tx fee (as a percentage of the minimum tx fee)
constexpr uint64_t BLINK_BURN_FIXED           = 0;  // A fixed amount (in atomic currency units) that the sender must burn
constexpr uint64_t BLINK_BURN_TX_FEE_PERCENT  = 150; // A percentage of the minimum miner tx fee that the sender must burn.  (Adds to BLINK_BURN_FIXED)

// FIXME: can remove this post-fork 15; the burned amount only matters for mempool acceptance and
// blink quorum signing, but isn't part of the blockchain concensus rules (so we don't actually have
// to keep it around in the code for syncing the chain).
constexpr uint64_t BLINK_BURN_TX_FEE_PERCENT_OLD = 400; // A percentage of the minimum miner tx fee that the sender must burn.  (Adds to BLINK_BURN_FIXED)

static_assert(BLINK_MINER_TX_FEE_PERCENT >= 100, "blink miner fee cannot be smaller than the base tx fee");
static_assert(BLINK_BURN_FIXED >= 0, "fixed blink burn amount cannot be negative");
static_assert(BLINK_BURN_TX_FEE_PERCENT >= 0, "blink burn tx percent cannot be negative");

// -------------------------------------------------------------------------------------------------
//
// LNS
//
// -------------------------------------------------------------------------------------------------
namespace lns
{
enum struct mapping_type : uint16_t
{
  session = 0,
  wallet = 1,
  gyuanxnet = 2, // the type value stored in the database; counts as 1-year when used in a buy tx.
  gyuanxnet_2years,
  gyuanxnet_5years,
  gyuanxnet_10years,
  _count,
  update_record_internal,
};

constexpr bool is_gyuanxnet_type(mapping_type t) { return t >= mapping_type::gyuanxnet && t <= mapping_type::gyuanxnet_10years; }

// How many days we add per "year" of LNS gyuanxnet registration.  We slightly extend this to the 368
// days per registration "year" to allow for some blockchain time drift + leap years.
constexpr uint64_t REGISTRATION_YEAR_DAYS = 368;

constexpr uint64_t burn_needed(uint8_t hf_version, mapping_type type)
{
  uint64_t result = 0;

  // The base amount for session/wallet/gyuanxnet-1year:
  const uint64_t basic_fee = (
      hf_version >= 16 ? 15*COIN :  // cryptonote::network_version_16_pulse -- but don't want to add cryptonote_config.h include
      20*COIN                       // cryptonote::network_version_15_lns
  );
  switch (type)
  {
    case mapping_type::update_record_internal:
      result = 0;
      break;

    case mapping_type::gyuanxnet: /* FALLTHRU */
    case mapping_type::session: /* FALLTHRU */
    case mapping_type::wallet: /* FALLTHRU */
    default:
      result = basic_fee;
      break;

    case mapping_type::gyuanxnet_2years: result = 2 * basic_fee; break;
    case mapping_type::gyuanxnet_5years: result = 4 * basic_fee; break;
    case mapping_type::gyuanxnet_10years: result = 6 * basic_fee; break;
  }
  return result;
}
};



constexpr auto TARGET_BLOCK_TIME           = 2min;
constexpr uint64_t DIFFICULTY_WINDOW       = 59;
constexpr uint64_t DIFFICULTY_BLOCKS_COUNT(bool before_hf16)
{
  // NOTE: We used to have a different setup here where,
  // DIFFICULTY_WINDOW       = 60
  // DIFFICULTY_BLOCKS_COUNT = 61
  // next_difficulty_v2's  N = DIFFICULTY_WINDOW - 1
  //
  // And we resized timestamps/difficulties to (N+1) (chopping off the latest timestamp).
  //
  // Now we re-adjust DIFFICULTY_WINDOW to 59. To preserve the old behaviour we
  // add +2. After HF16 we avoid trimming the top block and just add +1.
  //
  // Ideally, we just set DIFFICULTY_BLOCKS_COUNT to DIFFICULTY_WINDOW
  // + 1 for before and after HF16 (having one unified constant) but this
  // requires some more investigation to get it working with pre HF16 blocks and
  // alt chain code without bugs.
  uint64_t result = (before_hf16) ? DIFFICULTY_WINDOW + 2 : DIFFICULTY_WINDOW + 1;
  return result;
}

constexpr uint64_t BLOCKS_EXPECTED_IN_HOURS(int hours) { return (1h / TARGET_BLOCK_TIME) * hours; }
constexpr uint64_t BLOCKS_EXPECTED_IN_DAYS(int days)   { return BLOCKS_EXPECTED_IN_HOURS(24) * days; }
constexpr uint64_t BLOCKS_EXPECTED_IN_YEARS(int years) { return BLOCKS_EXPECTED_IN_DAYS(365) * years; }

#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_SECONDS_V2   TARGET_BLOCK_TIME * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
#define CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS       1


#define BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT          10000  //by default, blocks ids count in synchronizing
#define BLOCKS_SYNCHRONIZING_DEFAULT_COUNT              100    //by default, blocks count in blocks downloading
#define BLOCKS_SYNCHRONIZING_MAX_COUNT                  2048   //must be a power of 2, greater than 128, equal to SEEDHASH_EPOCH_BLOCKS

#define CRYPTONOTE_MEMPOOL_TX_LIVETIME                    (86400*3) //seconds, three days
#define CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME     (86400*7) //seconds, one week

#define MEMPOOL_PRUNE_NON_STANDARD_TX_LIFETIME          (2 * 60 * 60) // seconds, 2 hours
// see src/cryptonote_protocol/levin_notify.cpp
#define CRYPTONOTE_NOISE_MIN_EPOCH                      5      // minutes
#define CRYPTONOTE_NOISE_EPOCH_RANGE                    30     // seconds
#define CRYPTONOTE_NOISE_MIN_DELAY                      10     // seconds
#define CRYPTONOTE_NOISE_DELAY_RANGE                    5      // seconds
#define CRYPTONOTE_NOISE_BYTES                          3*1024 // 3 KiB
#define CRYPTONOTE_NOISE_CHANNELS                       2      // Max outgoing connections per zone used for noise/covert sending

#define CRYPTONOTE_MAX_FRAGMENTS                        20 // ~20 * NOISE_BYTES max payload size for covert/noise send


#define P2P_LOCAL_WHITE_PEERLIST_LIMIT                  1000
#define P2P_LOCAL_GRAY_PEERLIST_LIMIT                   5000

#define P2P_DEFAULT_CONNECTIONS_COUNT_OUT               8
#define P2P_DEFAULT_CONNECTIONS_COUNT_IN                32
#define P2P_DEFAULT_HANDSHAKE_INTERVAL                  60           //secondes
#define P2P_DEFAULT_PACKET_MAX_SIZE                     50000000     //50000000 bytes maximum packet size
#define P2P_DEFAULT_PEERS_IN_HANDSHAKE                  250
#define P2P_DEFAULT_CONNECTION_TIMEOUT                  5000       //5 seconds
#define P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT               45         // seconds
#define P2P_DEFAULT_PING_CONNECTION_TIMEOUT             2000       //2 seconds
#define P2P_DEFAULT_INVOKE_TIMEOUT                      60*2*1000  //2 minutes
#define P2P_DEFAULT_HANDSHAKE_INVOKE_TIMEOUT            5000       //5 seconds
#define P2P_DEFAULT_WHITELIST_CONNECTIONS_PERCENT       70
#define P2P_DEFAULT_ANCHOR_CONNECTIONS_COUNT            2
#define P2P_DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT       2
#define P2P_DEFAULT_LIMIT_RATE_UP                       2048       // kB/s
#define P2P_DEFAULT_LIMIT_RATE_DOWN                     8192       // kB/s

#define P2P_FAILED_ADDR_FORGET_SECONDS                  (60*60)     //1 hour
#define P2P_IP_BLOCKTIME                                (60*60*24)  //24 hour
#define P2P_IP_FAILS_BEFORE_BLOCK                       10
#define P2P_IDLE_CONNECTION_KILL_INTERVAL               (5*60) //5 minutes

// TODO(doyle): Deprecate after checkpointing hardfork, remove notion of being
// able to sync non-fluffy blocks, keep here so we can still accept blocks
// pre-hardfork
#define P2P_SUPPORT_FLAG_FLUFFY_BLOCKS                  0x01
#define P2P_SUPPORT_FLAGS                               P2P_SUPPORT_FLAG_FLUFFY_BLOCKS

#define CRYPTONOTE_NAME                         "gyuanx"
#define CRYPTONOTE_POOLDATA_FILENAME            "poolstate.bin"
#define CRYPTONOTE_BLOCKCHAINDATA_FILENAME      "data.mdb"
#define CRYPTONOTE_BLOCKCHAINDATA_LOCK_FILENAME "lock.mdb"
#define P2P_NET_DATA_FILENAME                   "p2pstate.bin"
#define MINER_CONFIG_FILE_NAME                  "miner_conf.json"

#define THREAD_STACK_SIZE                       5 * 1024 * 1024

#define HF_VERSION_PER_BYTE_FEE                 cryptonote::network_version_10_bulletproofs
#define HF_VERSION_SMALLER_BP                   cryptonote::network_version_11_infinite_staking
#define HF_VERSION_LONG_TERM_BLOCK_WEIGHT       cryptonote::network_version_11_infinite_staking
#define HF_VERSION_INCREASE_FEE                 cryptonote::network_version_12_checkpointing
#define HF_VERSION_PER_OUTPUT_FEE               cryptonote::network_version_13_enforce_checkpoints
#define HF_VERSION_ED25519_KEY                  cryptonote::network_version_13_enforce_checkpoints
#define HF_VERSION_FEE_BURNING                  cryptonote::network_version_14_blink
#define HF_VERSION_BLINK                        cryptonote::network_version_14_blink
#define HF_VERSION_MIN_2_OUTPUTS                cryptonote::network_version_16_pulse
#define HF_VERSION_REJECT_SIGS_IN_COINBASE      cryptonote::network_version_16_pulse
#define HF_VERSION_ENFORCE_MIN_AGE              cryptonote::network_version_16_pulse
#define HF_VERSION_EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY cryptonote::network_version_16_pulse
#define HF_VERSION_PULSE cryptonote::network_version_16_pulse
#define HF_VERSION_CLSAG                        cryptonote::network_version_16_pulse

#define PER_KB_FEE_QUANTIZATION_DECIMALS        8

#define HASH_OF_HASHES_STEP                     256

#define DEFAULT_TXPOOL_MAX_WEIGHT               648000000ull // 3 days at 300000, in bytes

#define BULLETPROOF_MAX_OUTPUTS                 16

#define CRYPTONOTE_PRUNING_STRIPE_SIZE          4096 // the smaller, the smoother the increase
#define CRYPTONOTE_PRUNING_LOG_STRIPES          3 // the higher, the more space saved
#define CRYPTONOTE_PRUNING_TIP_BLOCKS           5500 // the smaller, the more space saved
//#define CRYPTONOTE_PRUNING_DEBUG_SPOOF_SEED

// New constants are intended to go here
namespace config
{
  inline constexpr auto DNS_TIMEOUT = 20s;
  inline constexpr uint64_t DEFAULT_FEE_ATOMIC_XMR_PER_KB = 500; // Just a placeholder!  Change me!
  inline constexpr uint8_t FEE_CALCULATION_MAX_RETRIES = 10;
  inline constexpr uint64_t DEFAULT_DUST_THRESHOLD = 2000000000; // 2 * pow(10, 9)
  inline constexpr uint64_t BASE_REWARD_CLAMP_THRESHOLD = 100000000; // pow(10, 8)

  // Maximum allowed stake contribution, as a fraction of the available contribution room.  This
  // should generally be slightly larger than 1.  This is used to disallow large overcontributions
  // which can happen when there are competing stakes submitted at the same time for the same
  // service node.
  using MAXIMUM_ACCEPTABLE_STAKE = std::ratio<101, 100>;

  // Used to estimate the blockchain height from a timestamp, with some grace time.  This can drift
  // slightly over time (because average block time is not typically *exactly*
  // DIFFICULTY_TARGET_V2).
  inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 582088;
  inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1595359932;

  inline constexpr uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 114;
  inline constexpr uint64_t CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 115;
  inline constexpr uint64_t CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 116;
  inline constexpr uint16_t P2P_DEFAULT_PORT = 11011;
  inline constexpr uint16_t RPC_DEFAULT_PORT = 11013;
  inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 11014;
  inline constexpr uint16_t QNET_DEFAULT_PORT = 11015;
  inline constexpr boost::uuids::uuid const NETWORK_ID = { {
        0x49, 0x65, 0x70, 0x65 ,0x64, 0x75, 0x72, 0x44, 0x2a, 0x4c, 0x61, 0x75, 0x58, 0x65, 0x79
    } }; // Bender's nightmare
  inline constexpr std::string_view GENESIS_TX = "013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a28e9d0bc890d1"sv;
  inline constexpr uint32_t GENESIS_NONCE = 70;

  inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = BLOCKS_EXPECTED_IN_DAYS(7);
  inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
  {
    "L7VQJ4982Kd68T1ydjSmn26YGBu2C8vDoATChCkSSqCmQpYajU2RGM83FtQu2gpuGH5krzHfWvsNnY8iWJt9UdF156eCbRB"sv, // hardfork v7-10
    "L7VQJ4982Kd68T1ydjSmn26YGBu2C8vDoATChCkSSqCmQpYajU2RGM83FtQu2gpuGH5krzHfWvsNnY8iWJt9UdF156eCbRB"sv, // hardfork v11
  };

  // Hash domain separators
  inline constexpr std::string_view HASH_KEY_BULLETPROOF_EXPONENT = "bulletproof"sv;
  inline constexpr std::string_view HASH_KEY_RINGDB = "ringdsb\0"sv;
  inline constexpr std::string_view HASH_KEY_SUBADDRESS = "SubAddr\0"sv;
  inline constexpr unsigned char HASH_KEY_ENCRYPTED_PAYMENT_ID = 0x8d;
  inline constexpr unsigned char HASH_KEY_WALLET = 0x8c;
  inline constexpr unsigned char HASH_KEY_WALLET_CACHE = 0x8d;
  inline constexpr unsigned char HASH_KEY_RPC_PAYMENT_NONCE = 0x58;
  inline constexpr unsigned char HASH_KEY_MEMORY = 'k';
  inline constexpr std::string_view HASH_KEY_MULTISIG = "Multisig\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"sv;
  inline constexpr std::string_view HASH_KEY_CLSAG_ROUND = "CLSAG_round"sv;
  inline constexpr std::string_view HASH_KEY_CLSAG_AGG_0 = "CLSAG_agg_0"sv;
  inline constexpr std::string_view HASH_KEY_CLSAG_AGG_1 = "CLSAG_agg_1"sv;

  namespace testnet
  {
    inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 339767;
    inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1595360006;
    inline constexpr uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 156;
    inline constexpr uint64_t CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 157;
    inline constexpr uint64_t CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 158;
    inline constexpr uint16_t P2P_DEFAULT_PORT = 48156;
    inline constexpr uint16_t RPC_DEFAULT_PORT = 48157;
    inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 48158;
    inline constexpr uint16_t QNET_DEFAULT_PORT = 48159;
    inline constexpr boost::uuids::uuid const NETWORK_ID = { {
        0x70, 0x56, 0x78, 0x44, 0x59, 0x72, 0x58, 0xb8, 0x02, 0xa1, 0x44, 0x59, 0x61, 0x64, 0x15, 0xbe,
      } }; // Bender's daydream
    inline constexpr std::string_view GENESIS_TX = "03011e001e01ff00018080c9db97f4fb270259b546996f69aa71abe4238995f41d780ab1abebcac9f00e808f147bdb9e3228420112573af8c309b69a1a646f41b5212ba7d9c4590bf86e04f36c486467cfef9d3d72000000000000000000000000000000000000000000000000000000000000000000"sv;
    inline constexpr uint32_t GENESIS_NONCE = 70;

    inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 1000;
    inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
    {
      "T6SDQWrj1G2LRT9gaekQDxKQk9Snfi7UrhtFGCVcbjJm72L5CJ4yE4BUBvWAFCeQbbXkpa82w1SPyW14i2Y54uev2cAa7YbGQ"sv, // hardfork v7-9
      "T6SDQWrj1G2LRT9gaekQDxKQk9Snfi7UrhtFGCVcbjJm72L5CJ4yE4BUBvWAFCeQbbXkpa82w1SPyW14i2Y54uev2cAa7YbGQ"sv, // hardfork v10
    };

  }

  namespace devnet
  {
    inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 0;
    inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1597170000;
    inline constexpr uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX = 3930; // ~ dV1 .. dV3
    inline constexpr uint64_t CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 4442; // ~ dVA .. dVC
    inline constexpr uint64_t CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX = 5850; // ~dVa .. dVc
    inline constexpr uint16_t P2P_DEFAULT_PORT = 37856;
    inline constexpr uint16_t RPC_DEFAULT_PORT = 37857;
    inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 37858;
    inline constexpr uint16_t QNET_DEFAULT_PORT = 37859;
    inline constexpr boost::uuids::uuid const NETWORK_ID = { {
        0xa9, 0xf7, 0x55, 0x72, 0x55, 0x17, 0x55, 0x48, 0x50, 0xf4, 0x63, 0x78, 0x7a, 0x57, 0xab, 0xd3
      } };
    inline constexpr std::string_view GENESIS_TX = "04011e1e01ff00018080c9db97f4fb2702fa27e905f604faa4eb084ee675faca77b0cfea9adec1526da33cae5e286f31624201dae05bf3fa1662b7fd373c92426763d921cf3745e10ee43edb510f690c656f247200000000000000000000000000000000000000000000000000000000000000000000"sv;
    inline constexpr uint32_t GENESIS_NONCE = 70;

    inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = BLOCKS_EXPECTED_IN_DAYS(7);
    inline constexpr std::array GOVERNANCE_WALLET_ADDRESS =
    {
      "dV3EhSE1xXgSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M4A7Uimp"sv, // hardfork v7-9
      "dV3EhSE1xXgSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M4A7Uimp"sv, // hardfork v10
    };
  }
}

namespace cryptonote
{
  enum network_version
  {
    network_version_7 = 7,
    network_version_8,
    network_version_9_gnodes, // Proof Of Stake w/ Service Nodes
    network_version_10_bulletproofs, // Bulletproofs, Service Node Grace Registration Period, Batched Governance
    network_version_11_infinite_staking, // Infinite Staking, CN-Turtle
    network_version_12_checkpointing, // Checkpointing, Relaxed Deregistration, RandomXL, Gyuanx Storage Server
    network_version_13_enforce_checkpoints,
    network_version_14_blink,
    network_version_15_lns,
    network_version_16_pulse,
    network_version_17, // future HF

    network_version_count,
  };

  enum network_type : uint8_t
  {
    MAINNET = 0,
    TESTNET,
    DEVNET,
    FAKECHAIN,
    UNDEFINED = 255
  };

  inline constexpr std::string_view network_type_str(network_type nettype)
  {
    switch(nettype)
    {
      case MAINNET: return "Mainnet"sv;
      case TESTNET: return "Testnet"sv;
      case DEVNET: return "Devnet"sv;
      case FAKECHAIN: return "Fakenet"sv;
      case UNDEFINED: return "Undefined Net"sv;
    }
    return "Unhandled Net"sv;
  }

  struct network_config
  {
    network_type NETWORK_TYPE;
    uint64_t HEIGHT_ESTIMATE_HEIGHT;
    time_t HEIGHT_ESTIMATE_TIMESTAMP;
    uint64_t CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX;
    uint16_t P2P_DEFAULT_PORT;
    uint16_t RPC_DEFAULT_PORT;
    uint16_t ZMQ_RPC_DEFAULT_PORT;
    uint16_t QNET_DEFAULT_PORT;
    boost::uuids::uuid NETWORK_ID;
    std::string_view GENESIS_TX;
    uint32_t GENESIS_NONCE;
    uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS;
    std::array<std::string_view, 2> GOVERNANCE_WALLET_ADDRESS;

    inline constexpr std::string_view governance_wallet_address(int hard_fork_version) const {
      const auto wallet_switch =
        (NETWORK_TYPE == MAINNET || NETWORK_TYPE == FAKECHAIN)
        ? network_version_11_infinite_staking
        : network_version_10_bulletproofs;
      return GOVERNANCE_WALLET_ADDRESS[hard_fork_version >= wallet_switch ? 1 : 0];
    }
  };
  inline constexpr network_config mainnet_config = {
    MAINNET,
    ::config::HEIGHT_ESTIMATE_HEIGHT,
    ::config::HEIGHT_ESTIMATE_TIMESTAMP,
    ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
    ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
    ::config::P2P_DEFAULT_PORT,
    ::config::RPC_DEFAULT_PORT,
    ::config::ZMQ_RPC_DEFAULT_PORT,
    ::config::QNET_DEFAULT_PORT,
    ::config::NETWORK_ID,
    ::config::GENESIS_TX,
    ::config::GENESIS_NONCE,
    ::config::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
    ::config::GOVERNANCE_WALLET_ADDRESS,
  };
  inline constexpr network_config testnet_config = {
    TESTNET,
    ::config::testnet::HEIGHT_ESTIMATE_HEIGHT,
    ::config::testnet::HEIGHT_ESTIMATE_TIMESTAMP,
    ::config::testnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
    ::config::testnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    ::config::testnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
    ::config::testnet::P2P_DEFAULT_PORT,
    ::config::testnet::RPC_DEFAULT_PORT,
    ::config::testnet::ZMQ_RPC_DEFAULT_PORT,
    ::config::testnet::QNET_DEFAULT_PORT,
    ::config::testnet::NETWORK_ID,
    ::config::testnet::GENESIS_TX,
    ::config::testnet::GENESIS_NONCE,
    ::config::testnet::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
    ::config::testnet::GOVERNANCE_WALLET_ADDRESS,
  };
  inline constexpr network_config devnet_config = {
    DEVNET,
    ::config::devnet::HEIGHT_ESTIMATE_HEIGHT,
    ::config::devnet::HEIGHT_ESTIMATE_TIMESTAMP,
    ::config::devnet::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
    ::config::devnet::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    ::config::devnet::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
    ::config::devnet::P2P_DEFAULT_PORT,
    ::config::devnet::RPC_DEFAULT_PORT,
    ::config::devnet::ZMQ_RPC_DEFAULT_PORT,
    ::config::devnet::QNET_DEFAULT_PORT,
    ::config::devnet::NETWORK_ID,
    ::config::devnet::GENESIS_TX,
    ::config::devnet::GENESIS_NONCE,
    ::config::devnet::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
    ::config::devnet::GOVERNANCE_WALLET_ADDRESS,
  };
  inline constexpr network_config fakenet_config = {
    FAKECHAIN,
    ::config::HEIGHT_ESTIMATE_HEIGHT,
    ::config::HEIGHT_ESTIMATE_TIMESTAMP,
    ::config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
    ::config::CRYPTONOTE_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
    ::config::CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX,
    ::config::P2P_DEFAULT_PORT,
    ::config::RPC_DEFAULT_PORT,
    ::config::ZMQ_RPC_DEFAULT_PORT,
    ::config::QNET_DEFAULT_PORT,
    ::config::NETWORK_ID,
    ::config::GENESIS_TX,
    ::config::GENESIS_NONCE,
    100, //::config::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
    ::config::GOVERNANCE_WALLET_ADDRESS,
  };

  inline constexpr const network_config& get_config(network_type nettype)
  {
    switch (nettype)
    {
      case MAINNET: return mainnet_config;
      case TESTNET: return testnet_config;
      case DEVNET: return devnet_config;
      case FAKECHAIN: return fakenet_config;
      default: throw std::runtime_error{"Invalid network type"};
    }
  }
}
