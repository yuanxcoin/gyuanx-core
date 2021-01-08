// Copyright (c) 2014-2018, The Monero Project
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

#include "gyuanx_tests.h"
#include "common/string_util.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/gyuanx_name_system.h"
#include "cryptonote_core/gnode_list.h"
#include "common/random.h"

extern "C"
{
#include <sodium.h>
};

static void add_gnodes(gyuanx_chain_generator &gen, size_t count)
{
  std::vector<cryptonote::transaction> registration_txs(count);
  for (auto i = 0u; i < count; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);
}

#undef GYUANX_DEFAULT_LOG_CATEGORY
#define GYUANX_DEFAULT_LOG_CATEGORY "sn_core_tests"

// Suppose we have checkpoint and alt block at height 40 and the main chain is at height 40 with a differing block.
// Main chain receives checkpoints for height 40 on the alt chain via votes and reorgs back to height 39.
// Now main chain has an alt block sitting in its DB for height 40 which actually starts beyond the chain.

// In Monero land this is NOT ok because of the check in build_alt_chain
// CHECK_AND_ASSERT_MES(m_db->height() > alt_chain.front().height, false, "main blockchain wrong height");
// Where (m_db->height() == 40 and alt_chain.front().height == 40)

// So, we change the > to a >= because it appears the code handles it fine and
// it saves us from having to delete our alt_blocks and have to re-receive the
// block over P2P again "just so that it can go through the normal block added
// code path" again
bool gyuanx_checkpointing_alt_chain_handle_alt_blocks_at_tip::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();
  add_gnodes(gen, gnodes::CHECKPOINT_QUORUM_SIZE);

  // NOTE: Create next block on checkpoint boundary and add checkpoiont

  gyuanx_chain_generator fork = gen;
  gen.add_blocks_until_next_checkpointable_height();
  fork.add_blocks_until_next_checkpointable_height();
  fork.add_gnode_checkpoint(fork.height(), gnodes::CHECKPOINT_MIN_VOTES);

  // NOTE: Though we receive a checkpoint via votes, the alt block is still in
  // the alt db because we don't trigger a chain switch until we receive a 2nd
  // block that confirms the alt block.
  uint64_t curr_height   = gen.height();
  crypto::hash curr_hash = get_block_hash(gen.top().block);
  gyuanx_register_callback(events, "check_alt_block_count", [curr_height, curr_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_alt_block_count");

    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(top_height, curr_height);
    CHECK_EQ(top_hash, curr_hash);
    CHECK_TEST_CONDITION(c.get_blockchain_storage().get_alternative_blocks_count() > 0);
    return true;
  });

  // NOTE: We add a new block ontop that causes the alt block code path to run
  // again, and calculate that this alt chain now has 2 blocks on it with
  // now same difficulty but more checkpoints, causing a chain switch at this point.
  gen.add_blocks_until_next_checkpointable_height();
  fork.add_blocks_until_next_checkpointable_height();
  fork.add_gnode_checkpoint(fork.height(), gnodes::CHECKPOINT_MIN_VOTES);

  gen.create_and_add_next_block();
  fork.create_and_add_next_block();

  crypto::hash expected_top_hash = cryptonote::get_block_hash(fork.top().block);
  gyuanx_register_callback(events, "check_chain_reorged", [expected_top_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_chain_reorged");
    CHECK_EQ(c.get_blockchain_storage().get_alternative_blocks_count(), 0);
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(expected_top_hash, top_hash);
    return true;
  });
  return true;
}

// NOTE: - Checks that a chain with a checkpoint but less PoW is preferred over a chain that is longer with more PoW but no checkpoints
bool gyuanx_checkpointing_alt_chain_more_gnode_checkpoints_less_pow_overtakes::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  int constexpr NUM_SERVICE_NODES = gnodes::CHECKPOINT_QUORUM_SIZE;
  std::vector<cryptonote::transaction> registration_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);

  gen.add_blocks_until_next_checkpointable_height();
  gyuanx_chain_generator fork_with_more_checkpoints = gen;
  gen.add_n_blocks(60); // Add blocks so that this chain has more PoW

  cryptonote::checkpoint_t checkpoint = fork_with_more_checkpoints.create_gnode_checkpoint(fork_with_more_checkpoints.height(), gnodes::CHECKPOINT_MIN_VOTES);
  fork_with_more_checkpoints.create_and_add_next_block({}, &checkpoint);
  uint64_t const fork_top_height   = cryptonote::get_block_height(fork_with_more_checkpoints.top().block);
  crypto::hash const fork_top_hash = cryptonote::get_block_hash(fork_with_more_checkpoints.top().block);

  gyuanx_register_callback(events, "check_switched_to_alt_chain", [fork_top_hash, fork_top_height](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_switched_to_alt_chain");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(top_height, fork_top_height);
    CHECK_EQ(top_hash, fork_top_hash);
    return true;
  });
  return true;
}

// NOTE: - A chain that receives checkpointing votes sufficient to form a checkpoint should reorg back accordingly
bool gyuanx_checkpointing_alt_chain_receive_checkpoint_votes_should_reorg_back::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  int constexpr NUM_SERVICE_NODES = gnodes::CHECKPOINT_QUORUM_SIZE;
  std::vector<cryptonote::transaction> registration_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);

  gen.add_event_msg("Add blocks until we get to the first height that has a checkpointing quorum AND there are service nodes in the quorum.");
  gen.add_blocks_until_next_checkpointable_height();

  gen.add_event_msg("Diverge the two chains in tandem, so they have the same PoW and generate alt service node states, but still remain on the mainchain due to PoW");
  gyuanx_chain_generator fork = gen;
  for (size_t i = 0; i < gnodes::CHECKPOINT_INTERVAL; i++)
  {
    gen.create_and_add_next_block();
    fork.create_and_add_next_block();
  }

  gen.add_event_msg("Fork generate two checkpoints worth of blocks.");
  uint64_t first_checkpointed_height    = fork.height();
  uint64_t first_checkpointed_height_hf = fork.top().block.major_version;
  crypto::hash first_checkpointed_hash  = cryptonote::get_block_hash(fork.top().block);
  std::shared_ptr<const gnodes::quorum> first_quorum = fork.get_quorum(gnodes::quorum_type::checkpointing, gen.height());

  for (size_t i = 0; i < gnodes::CHECKPOINT_INTERVAL; i++)
  {
    gen.create_and_add_next_block();
    fork.create_and_add_next_block();
  }

  gen.add_event_msg(
      "Fork generates service node votes, upon sending them over and the main chain collecting them validly (they "
      "should be able to verify signatures because we store alt quorums) it should generate a checkpoint belonging to "
      "the forked chain- which should cause it to detach back to the checkpoint height");

  gen.add_event_msg(
      "Then we send the votes for the 2nd newest checkpoint. We don't reorg back until we receive a block confirming "
      "this checkpoint.");
  for (size_t i = 0; i < gnodes::CHECKPOINT_MIN_VOTES; i++)
  {
    auto keys = gen.get_cached_keys(first_quorum->validators[i]);
    gnodes::quorum_vote_t fork_vote = gnodes::make_checkpointing_vote(first_checkpointed_height_hf, first_checkpointed_hash, first_checkpointed_height, i, keys);
    events.push_back(gyuanx_blockchain_addable<gnodes::quorum_vote_t>(fork_vote, true/*can_be_added_to_blockchain*/, "A first_checkpoint vote from the forked chain should be accepted since we should be storing alternative service node states and quorums"));
  }

  gen.add_event_msg("Upon adding the last block, we should now switch to our forked chain");
  fork.create_and_add_next_block({});
  crypto::hash const fork_top_hash = cryptonote::get_block_hash(fork.top().block);
  gyuanx_register_callback(events, "check_switched_to_alt_chain", [fork_top_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_switched_to_alt_chain");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(fork_top_hash, top_hash);
    return true;
  });
  return true;
}

bool gyuanx_checkpointing_alt_chain_too_old_should_be_dropped::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  int constexpr NUM_SERVICE_NODES = gnodes::CHECKPOINT_QUORUM_SIZE;
  std::vector<cryptonote::transaction> registration_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);

  gyuanx_chain_generator fork = gen;
  gen.add_blocks_until_next_checkpointable_height();
  fork.add_blocks_until_next_checkpointable_height();
  gen.add_gnode_checkpoint(gen.height(), gnodes::CHECKPOINT_MIN_VOTES);

  gen.add_blocks_until_next_checkpointable_height();
  fork.add_blocks_until_next_checkpointable_height();
  gen.add_gnode_checkpoint(gen.height(), gnodes::CHECKPOINT_MIN_VOTES);

  gen.add_blocks_until_next_checkpointable_height();
  gen.add_gnode_checkpoint(gen.height(), gnodes::CHECKPOINT_MIN_VOTES);

  // NOTE: We now have 3 checkpoints. Extending this alt-chain is no longer
  // possible because this alt-chain starts before the immutable height, it
  // should be deleted and removed.
  fork.create_and_add_next_block({}, nullptr, false, "Can not add block to alt chain because the alt chain starts before the immutable height. Those blocks should be locked into the chain");
  return true;
}

// NOTE: - Checks that an alt chain eventually takes over the main chain with
// only 1 checkpoint, by progressively adding 2 more checkpoints at the next
// available checkpoint heights whilst maintaining equal heights with the main chain
bool gyuanx_checkpointing_alt_chain_with_increasing_gnode_checkpoints::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();
  add_gnodes(gen, gnodes::CHECKPOINT_QUORUM_SIZE);

  gen.add_blocks_until_next_checkpointable_height();

  // Setup the two chains as follows, where C = checkpointed block, B = normal
  // block, the main chain should NOT reorg to the fork chain as they have the
  // same PoW-ish and equal number of checkpoints.
  // Main chain   C B B B B
  // Fork chain   B B B B C

  gyuanx_chain_generator fork = gen;
  gen.add_gnode_checkpoint(gen.height(), gnodes::CHECKPOINT_MIN_VOTES);

  gen.add_blocks_until_next_checkpointable_height();
  fork.add_blocks_until_next_checkpointable_height();
  fork.add_gnode_checkpoint(fork.height(), gnodes::CHECKPOINT_MIN_VOTES);

  crypto::hash const gen_top_hash = cryptonote::get_block_hash(gen.top().block);
  gyuanx_register_callback(events, "check_still_on_main_chain", [gen_top_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_still_on_main_chain");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(top_hash, gen_top_hash);
    return true;
  });

  // Now create the following chain, the fork chain should be switched to due to now having more checkpoints
  // Main chain   C B B B B | B B B B B
  // Fork chain   B B B B C | B B B C
  gen.add_blocks_until_next_checkpointable_height();
  gen.create_and_add_next_block();

  fork.add_blocks_until_next_checkpointable_height();
  cryptonote::checkpoint_t fork_second_checkpoint = fork.create_gnode_checkpoint(fork.height(), gnodes::CHECKPOINT_MIN_VOTES);
  fork.create_and_add_next_block({}, &fork_second_checkpoint);

  crypto::hash const fork_top_hash = cryptonote::get_block_hash(fork.top().block);
  gyuanx_register_callback(events, "check_switched_to_alt_chain", [fork_top_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_switched_to_alt_chain");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(fork_top_hash, top_hash);
    return true;
  });
  return true;
}

// NOTE: - Checks checkpoints aren't generated until there are enough votes sitting in the vote pool
//       - Checks invalid vote (signature or key) is not accepted due to not being part of the quorum
bool gyuanx_checkpointing_gnode_checkpoint_from_votes::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();
  add_gnodes(gen, gnodes::CHECKPOINT_QUORUM_SIZE);

  // NOTE: Generate service node votes
  gen.add_blocks_until_next_checkpointable_height();
  uint64_t checkpointed_height                                = gen.height();
  crypto::hash checkpointed_hash                              = cryptonote::get_block_hash(gen.top().block);
  std::shared_ptr<const gnodes::quorum> quorum = gen.get_quorum(gnodes::quorum_type::checkpointing, gen.height());
  std::vector<gnodes::quorum_vote_t> checkpoint_votes(gnodes::CHECKPOINT_MIN_VOTES);
  for (size_t i = 0; i < gnodes::CHECKPOINT_MIN_VOTES; i++)
  {
    auto keys = gen.get_cached_keys(quorum->validators[i]);
    checkpoint_votes[i] = gnodes::make_checkpointing_vote(gen.top().block.major_version, checkpointed_hash, checkpointed_height, i, keys);
  }

  // NOTE: Submit invalid vote using service node keys not in the quorum
  {
    const cryptonote::keypair invalid_kp = cryptonote::keypair::generate(hw::get_device("default"));
    gnodes::gnode_keys invalid_keys;
    invalid_keys.pub = invalid_kp.pub;
    invalid_keys.key = invalid_kp.sec;

    gnodes::quorum_vote_t invalid_vote = gnodes::make_checkpointing_vote(gen.top().block.major_version, checkpointed_hash, checkpointed_height, 0, invalid_keys);
    gen.events_.push_back(gyuanx_blockchain_addable<decltype(invalid_vote)>(
        invalid_vote,
        false /*can_be_added_to_blockchain*/,
        "Can not add a vote that uses a service node key not part of the quorum"));
  }

  // NOTE: Add insufficient service node votes and check that no checkpoint is generated yet
  for (size_t i = 0; i < gnodes::CHECKPOINT_MIN_VOTES - 1; i++)
    gen.events_.push_back(gyuanx_blockchain_addable<gnodes::quorum_vote_t>(checkpoint_votes[i]));

  gyuanx_register_callback(events, "check_gnode_checkpoint_rejected_insufficient_votes", [checkpointed_height](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_gnode_checkpoint_rejected_insufficient_votes");
    cryptonote::Blockchain const &blockchain = c.get_blockchain_storage();
    cryptonote::checkpoint_t real_checkpoint;
    CHECK_TEST_CONDITION(blockchain.get_checkpoint(checkpointed_height, real_checkpoint) == false);
    return true;
  });

  // NOTE: Add last vote and check checkpoint has been generated
  gen.events_.push_back(checkpoint_votes.back());
  gyuanx_register_callback(events, "check_gnode_checkpoint_accepted", [checkpointed_height](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_gnode_checkpoint_accepted");
    cryptonote::Blockchain const &blockchain = c.get_blockchain_storage();
    cryptonote::checkpoint_t real_checkpoint;
    CHECK_TEST_CONDITION(blockchain.get_checkpoint(checkpointed_height, real_checkpoint));
    return true;
  });

  return true;
}

// NOTE: - Checks you can't add blocks before the first 2 checkpoints
//       - Checks you can add a block after the 1st checkpoint out of 2 checkpoints.
bool gyuanx_checkpointing_gnode_checkpoints_check_reorg_windows::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();
  add_gnodes(gen, gnodes::CHECKPOINT_QUORUM_SIZE);

  // NOTE: Add blocks until we get to the first height that has a checkpointing quorum AND there are service nodes in the quorum.
  int const MAX_TRIES = 16;
  int tries           = 0;
  for (; tries < MAX_TRIES; tries++)
  {
    gen.add_blocks_until_next_checkpointable_height();
    std::shared_ptr<const gnodes::quorum> quorum = gen.get_quorum(gnodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);

  gen.add_event_msg("Mine up until 1 block before the next checkpointable height, fork the chain.");
  gen.add_n_blocks(gnodes::CHECKPOINT_INTERVAL - 1);
  gyuanx_chain_generator fork_1_block_before_checkpoint = gen;

  gen.add_event_msg("Mine one block and fork the chain before we add the checkpoint.");
  gen.create_and_add_next_block();
  gen.add_gnode_checkpoint(gen.height(), gnodes::CHECKPOINT_MIN_VOTES);
  gyuanx_chain_generator fork_1_block_after_checkpoint = gen;

  gen.add_event_msg("Add the next service node checkpoints on the main chain to lock in the chain preceeding the first checkpoint");
  gen.add_n_blocks(gnodes::CHECKPOINT_INTERVAL - 1);
  gyuanx_chain_generator fork_1_block_before_second_checkpoint = gen;

  gen.create_and_add_next_block();
  gen.add_gnode_checkpoint(gen.height(), gnodes::CHECKPOINT_MIN_VOTES);

  gen.add_event_msg("Try add a block before first checkpoint, should fail because we are already 2 checkpoints deep.");
  fork_1_block_before_checkpoint.create_and_add_next_block({}, nullptr /*checkpoint*/, false /*can_be_added_to_blockchain*/, "Can NOT add a block if the height would equal the immutable height");

  gen.add_event_msg("Try add a block after the first checkpoint. This should succeed because we can reorg the chain within the 2 checkpoint window");
  fork_1_block_after_checkpoint.create_and_add_next_block({});

  gen.add_event_msg("Try add a block on the second checkpoint. This should also succeed because we can reorg the chain within the 2 checkpoint window, and although the height is checkpointed and should fail checkpoints::check, it should still be allowed as an alt block");
  fork_1_block_before_second_checkpoint.create_and_add_next_block({});
  return true;
}

bool gyuanx_core_block_reward_unpenalized_pre_pulse::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table(cryptonote::network_version_16_pulse - 1);
  gyuanx_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);

  uint8_t newest_hf = hard_forks.back().first;
  assert(newest_hf >= cryptonote::network_version_13_enforce_checkpoints);

  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base dummy = gen.add_account();
  int constexpr NUM_TXS          = 60;
  std::vector<cryptonote::transaction> txs(NUM_TXS);
  for (int i = 0; i < NUM_TXS; i++)
    txs[i] = gen.create_and_add_tx(gen.first_miner_, dummy.get_keys().m_account_address, MK_COINS(5));

  gen.create_and_add_next_block(txs);
  uint64_t unpenalized_block_reward     = cryptonote::block_reward_unpenalized_formula_v8(gen.height());
  uint64_t expected_gnode_reward = cryptonote::gnode_reward_formula(unpenalized_block_reward, newest_hf);

  gyuanx_register_callback(events, "check_block_rewards", [unpenalized_block_reward, expected_gnode_reward](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_block_rewards");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);

    bool orphan;
    cryptonote::block top_block;
    CHECK_TEST_CONDITION(c.get_block_by_hash(top_hash, top_block, &orphan));
    CHECK_TEST_CONDITION(orphan == false);
    CHECK_TEST_CONDITION_MSG(top_block.miner_tx.vout[0].amount < unpenalized_block_reward, "We should add enough transactions that the penalty is realised on the base block reward");
    CHECK_EQ(top_block.miner_tx.vout[1].amount, expected_gnode_reward);
    return true;
  });
  return true;
}

bool gyuanx_core_block_reward_unpenalized_post_pulse::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table(cryptonote::network_version_count -1, 150 /*Proof Of Stake Delay*/);
  gyuanx_chain_generator gen(events, hard_forks);

  uint8_t const newest_hf = hard_forks.back().first;
  assert(newest_hf >= cryptonote::network_version_13_enforce_checkpoints);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  // Make big chunky TX's to trigger the block size penalty
  cryptonote::account_base dummy = gen.add_account();
  uint64_t tx_fee = 0;
  std::vector<cryptonote::transaction> txs(150);
  for (size_t i = 0; i < txs.size(); i++)
  {
    std::array<gyuanx_gnode_contribution, 3> contributions = {};
    for (size_t i = 0; i < contributions.size(); i++)
    {
      gyuanx_gnode_contribution &entry = contributions[i];
      entry.contributor                     = gen.add_account().get_keys().m_account_address;
      entry.portions                        = STAKING_PORTIONS / 4;
    }

    txs[i] = gen.create_registration_tx(gen.first_miner(),
                                        cryptonote::keypair::generate(hw::get_device("default")),
                                        STAKING_PORTIONS / 4, /*operator portions*/
                                        0,                    /*operator cut*/
                                        contributions,
                                        3);
    gen.add_tx(txs[i], true /*can_be_added_to_blockchain*/, ""/*fail_msg*/, true /*kept_by_block*/);
    tx_fee += txs[i].rct_signatures.txnFee;
  }
  gen.create_and_add_next_block(txs);

  uint64_t unpenalized_reward = cryptonote::gnode_reward_formula(BLOCK_REWARD_HF17, newest_hf);
  gyuanx_register_callback(events, "check_block_rewards", [unpenalized_reward, tx_fee](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_block_rewards");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);

    bool orphan;
    cryptonote::block top_block;
    CHECK_TEST_CONDITION(c.get_block_by_hash(top_hash, top_block, &orphan));

    CHECK_TEST_CONDITION(orphan == false);

    uint64_t rewards_from_fee = top_block.miner_tx.vout[0].amount;
    CHECK_TEST_CONDITION_MSG(top_block.miner_tx.vout.size() == 2, "1 for miner, 1 for service node");
    CHECK_TEST_CONDITION_MSG(rewards_from_fee > 0 && rewards_from_fee < tx_fee, "Block producer should receive a penalised tx fee less than " << cryptonote::print_money(tx_fee) << "received, " << cryptonote::print_money(rewards_from_fee) << "");
    CHECK_TEST_CONDITION_MSG(top_block.miner_tx.vout[1].amount == unpenalized_reward, "Service Node should receive full reward " << unpenalized_reward);

    MGINFO("rewards_from_fee: "   << cryptonote::print_money(rewards_from_fee));
    MGINFO("tx_fee: "             << cryptonote::print_money(tx_fee));
    MGINFO("unpenalized_amount: " << cryptonote::print_money(unpenalized_reward));
    return true;
  });
  return true;
}

bool gyuanx_core_fee_burning::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);

  uint8_t newest_hf = hard_forks.back().first;
  assert(newest_hf >= cryptonote::network_version_14_blink);

  gen.add_mined_money_unlock_blocks();

  using namespace cryptonote;
  account_base dummy = gen.add_account();

  static constexpr std::array<std::array<uint64_t, 3>, 3> send_fee_burn{{
    {MK_COINS(5), MK_COINS(3), MK_COINS(1)},
    {MK_COINS(10), MK_COINS(5), MK_COINS(2)},
    {MK_COINS(5), MK_COINS(2), MK_COINS(1)},
  }};

  auto add_burning_tx = [&events, &gen, &dummy, newest_hf](const std::array<uint64_t, 3> &send_fee_burn) {
    auto send = send_fee_burn[0], fee = send_fee_burn[1], burn = send_fee_burn[2];
    transaction tx = gen.create_tx(gen.first_miner_, dummy.get_keys().m_account_address, send, fee);
    std::vector<uint8_t> burn_extra;
    add_burned_amount_to_tx_extra(burn_extra, burn);
    gyuanx_tx_builder(events, tx, gen.blocks().back().block, gen.first_miner_, dummy.get_keys().m_account_address, send, newest_hf).with_fee(fee).with_extra(burn_extra).build();
    gen.add_tx(tx);
    return tx;
  };

  std::vector<transaction> txs;
  for (size_t i = 0; i < 2; i++)
    txs.push_back(add_burning_tx(send_fee_burn[i]));

  gen.create_and_add_next_block(txs);
  auto good_hash = gen.blocks().back().block.hash;
  uint64_t good_miner_reward;

  {
    gyuanx_block_reward_context ctx{};
    ctx.height = get_block_height(gen.blocks().back().block);
    ctx.fee = send_fee_burn[0][1] + send_fee_burn[1][1] - send_fee_burn[0][2] - send_fee_burn[1][2];
    block_reward_parts reward_parts;
    cryptonote::get_gyuanx_block_reward(0, 0, 1 /*already generated, needs to be >0 to avoid premine*/, newest_hf, reward_parts, ctx);
    good_miner_reward = reward_parts.miner_fee + reward_parts.base_miner;
  }

  txs.clear();
  // Try to add another block with a fee that claims into the amount of the fee that must be burned
  txs.push_back(add_burning_tx(send_fee_burn[2]));

  {
    gyuanx_create_block_params block_params = gen.next_block_params();
    block_params.total_fee = send_fee_burn[2][1] - send_fee_burn[2][2] + 2;

    gyuanx_blockchain_entry next = {};
    bool created = gen.create_block(next, block_params, txs);
    assert(created);
    gen.add_block(next, false, "Invalid miner reward");
  }

  gyuanx_register_callback(events, "check_fee_burned", [good_hash, good_miner_reward](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_fee_burned");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);

    bool orphan;
    cryptonote::block top_block;
    CHECK_TEST_CONDITION(c.get_block_by_hash(top_hash, top_block, &orphan));
    CHECK_TEST_CONDITION(orphan == false);

    CHECK_EQ(top_hash, good_hash);

    CHECK_EQ(top_block.miner_tx.vout[0].amount, good_miner_reward);

    return true;
  });
  return true;
}

bool gyuanx_core_governance_batched_reward::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table(cryptonote::network_version_10_bulletproofs);

  uint64_t hf10_height = 0;
  for (std::pair<uint8_t, uint64_t> hf_pair : hard_forks)
  {
    if (hf_pair.first == cryptonote::network_version_10_bulletproofs)
    {
      hf10_height = hf_pair.second;
      break;
    }
  }
  assert(hf10_height != 0);

  uint64_t expected_total_governance_paid = 0;
  gyuanx_chain_generator batched_governance_generator(events, hard_forks);
  {
    batched_governance_generator.add_blocks_until_version(cryptonote::network_version_10_bulletproofs);
    constexpr auto& network = cryptonote::get_config(cryptonote::FAKECHAIN);
    uint64_t blocks_to_gen = network.GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS - batched_governance_generator.height();
    batched_governance_generator.add_n_blocks(blocks_to_gen);
  }

  {
    // NOTE(gyuanx): Since hard fork 8 we have an emissions curve change, so if
    // you don't atleast progress and generate blocks from hf8 you will run into
    // problems
    std::vector<std::pair<uint8_t, uint64_t>> other_hard_forks = {
        std::make_pair(cryptonote::network_version_7, 0),
        std::make_pair(cryptonote::network_version_8, 1),
        std::make_pair(cryptonote::network_version_9_gnodes, hf10_height)};

    std::vector<test_event_entry> unused_events;
    gyuanx_chain_generator no_batched_governance_generator(unused_events, other_hard_forks);
    no_batched_governance_generator.add_blocks_until_version(other_hard_forks.back().first);

    while(no_batched_governance_generator.height() < batched_governance_generator.height())
      no_batched_governance_generator.create_and_add_next_block();

    // NOTE(gyuanx): Skip the last block as that is the batched payout height, we
    // don't include the governance reward of that height, that gets picked up
    // in the next batch.
    const std::vector<gyuanx_blockchain_entry>& blockchain = no_batched_governance_generator.blocks();
    for (size_t block_height = hf10_height; block_height < blockchain.size() - 1; ++block_height)
    {
      const cryptonote::block &block = blockchain[block_height].block;
      expected_total_governance_paid += block.miner_tx.vout.back().amount;
    }
  }

  gyuanx_register_callback(events, "check_batched_governance_amount_matches", [hf10_height, expected_total_governance_paid](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_batched_governance_amount_matches");

    uint64_t height = c.get_current_blockchain_height();
    std::vector<cryptonote::block> blockchain;
    if (!c.get_blocks((uint64_t)0, (size_t)height, blockchain))
      return false;

    uint64_t governance = 0;
    for (size_t block_height = hf10_height; block_height < blockchain.size(); ++block_height)
    {
      const cryptonote::block &block = blockchain[block_height];
      if (cryptonote::block_has_governance_output(cryptonote::FAKECHAIN, block))
        governance += block.miner_tx.vout.back().amount;
    }

    CHECK_EQ(governance, expected_total_governance_paid);
    return true;
  });

  return true;
}

bool gyuanx_core_block_rewards_lrc6::generate(std::vector<test_event_entry>& events)
{
  constexpr auto& network = cryptonote::get_config(cryptonote::FAKECHAIN);
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table(cryptonote::network_version_15_lns);
  hard_forks.emplace_back(cryptonote::network_version_16_pulse, hard_forks.back().second + network.GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS + 10);
  hard_forks.emplace_back(cryptonote::network_version_17, hard_forks.back().second + network.GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS);
  gyuanx_chain_generator batched_governance_generator(events, hard_forks);
  batched_governance_generator.add_blocks_until_version(cryptonote::network_version_17);
  batched_governance_generator.add_n_blocks(network.GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS);

  uint64_t hf15_height = 0, hf16_height = 0, hf17_height = 0;
  for (const auto &hf : hard_forks)
  {
    if (hf.first == cryptonote::network_version_15_lns)
      hf15_height = hf.second;
    else if (hf.first == cryptonote::network_version_16_pulse)
      hf16_height = hf.second;
    else
      hf17_height = hf.second;
  }

  gyuanx_register_callback(events, "check_lrc6_7_block_rewards", [hf15_height, hf16_height, hf17_height, interval=network.GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_lrc6_7_block_rewards");

    uint64_t height = c.get_current_blockchain_height();
    std::vector<cryptonote::block> blockchain;
    if (!c.get_blocks((uint64_t)0, (size_t)height, blockchain))
      return false;

    int hf15_gov = 0, hf16_gov = 0, hf17_gov = 0;
    for (size_t block_height = hf15_height; block_height < hf16_height; ++block_height)
    {
      const cryptonote::block &block = blockchain[block_height];
      CHECK_EQ(block.miner_tx.vout.at(0).amount, MINER_REWARD_HF15);
      CHECK_EQ(block.miner_tx.vout.at(1).amount, SN_REWARD_HF15);
      if (cryptonote::block_has_governance_output(cryptonote::FAKECHAIN, block))
      {
        hf15_gov++;
        CHECK_EQ(block.miner_tx.vout.at(2).amount, FOUNDATION_REWARD_HF15 * interval);
        CHECK_EQ(block.miner_tx.vout.size(), 3);
      }
      else
        CHECK_EQ(block.miner_tx.vout.size(), 2);
    }

    for (size_t block_height = hf16_height; block_height < hf17_height; ++block_height)
    {
      const cryptonote::block &block = blockchain[block_height];
      CHECK_EQ(block.miner_tx.vout.at(0).amount, SN_REWARD_HF15);
      if (cryptonote::block_has_governance_output(cryptonote::FAKECHAIN, block))
      {
        hf16_gov++;
        CHECK_EQ(block.miner_tx.vout.at(1).amount, (FOUNDATION_REWARD_HF15 + CHAINFLIP_LIQUIDITY_HF16) * interval);
        CHECK_EQ(block.miner_tx.vout.size(), 2);
      }
      else
        CHECK_EQ(block.miner_tx.vout.size(), 1);
    }

    for (size_t block_height = hf17_height; block_height < height; ++block_height)
    {
      const cryptonote::block &block = blockchain[block_height];
      CHECK_EQ(block.miner_tx.vout.at(0).amount, SN_REWARD_HF15);
      if (cryptonote::block_has_governance_output(cryptonote::FAKECHAIN, block))
      {
        hf17_gov++;
        CHECK_EQ(block.miner_tx.vout.at(1).amount, FOUNDATION_REWARD_HF17 * interval);
        CHECK_EQ(block.miner_tx.vout.size(), 2);
      }
      else
        CHECK_EQ(block.miner_tx.vout.size(), 1);
    }

    CHECK_EQ(hf15_gov, 1);
    CHECK_EQ(hf16_gov, 1);
    CHECK_EQ(hf17_gov, 1);

    return true;
  });

  return true;
}

bool gyuanx_core_test_deregister_preferred::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table(cryptonote::network_version_9_gnodes);
  gyuanx_chain_generator gen(events, hard_forks);
  const auto miner                 = gen.first_miner();
  const auto alice                 = gen.add_account();

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(60); /// give miner some outputs to spend and unlock them
  gen.add_mined_money_unlock_blocks();
  add_gnodes(gen, 12);

  /// generate transactions to fill up txpool entirely
  for (auto i = 0u; i < 45; ++i) {
    gen.create_and_add_tx(miner, alice.get_keys().m_account_address, MK_COINS(1), TESTS_DEFAULT_FEE * 100);
  }

  /// generate two deregisters
  const auto deregister_pub_key_1 = gen.top_quorum().obligations->workers[0];
  const auto deregister_pub_key_2 = gen.top_quorum().obligations->workers[1];
  gen.create_and_add_state_change_tx(gnodes::new_state::deregister, deregister_pub_key_1);
  gen.create_and_add_state_change_tx(gnodes::new_state::deregister, deregister_pub_key_2);

  gyuanx_register_callback(events, "check_prefer_deregisters", [&events, miner](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_prefer_deregisters");
    const auto tx_count = c.get_pool().get_transactions_count();
    cryptonote::block full_blk;
    {
      cryptonote::difficulty_type diffic;
      uint64_t height;
      uint64_t expected_reward;
      cryptonote::blobdata extra_nonce;
      c.create_next_miner_block_template(full_blk, miner.get_keys().m_account_address, diffic, height, expected_reward, extra_nonce);
    }

    map_hash2tx_t mtx;
    {
      std::vector<cryptonote::block> chain;
      CHECK_TEST_CONDITION(find_block_chain(events, chain, mtx, get_block_hash(var::get<cryptonote::block>(events[0]))));
    }

    const auto deregister_count =
      std::count_if(full_blk.tx_hashes.begin(), full_blk.tx_hashes.end(), [&mtx](const crypto::hash& tx_hash) {
        return mtx[tx_hash]->type == cryptonote::txtype::state_change;
      });

    CHECK_TEST_CONDITION(tx_count > full_blk.tx_hashes.size()); /// test that there are more transactions in tx pool
    CHECK_EQ(deregister_count, 2);
    return true;
  });
  return true;
}

// Test if a person registers onto the network and they get included in the nodes to test (i.e. heights 0, 5, 10). If
// they get dereigstered in the nodes to test, height 5, and rejoin the network before height 10 (and are in the nodes
// to test), they don't get deregistered.
bool gyuanx_core_test_deregister_safety_buffer::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table(cryptonote::network_version_9_gnodes);
  gyuanx_chain_generator gen(events, hard_forks);
  const auto miner = gen.first_miner();

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(40); /// give miner some outputs to spend and unlock them
  gen.add_mined_money_unlock_blocks();
  add_gnodes(gen, gnodes::STATE_CHANGE_QUORUM_SIZE * 2 + 1);

  const auto height_a                      = gen.height();
  std::vector<crypto::public_key> quorum_a = gen.quorum(height_a).obligations->workers;

  gen.add_n_blocks(5); /// create 5 blocks and find public key to be tested twice

  const auto height_b                      = gen.height();
  std::vector<crypto::public_key> quorum_b = gen.quorum(height_b).obligations->workers;

  std::vector<crypto::public_key> quorum_intersection;
  for (const auto& pub_key : quorum_a)
  {
    if (std::find(quorum_b.begin(), quorum_b.end(), pub_key) != quorum_b.end())
      quorum_intersection.push_back(pub_key);
  }

  const auto deregister_pub_key = quorum_intersection[0];
  {
    const auto dereg_tx = gen.create_and_add_state_change_tx(gnodes::new_state::deregister, deregister_pub_key, height_a);
    gen.create_and_add_next_block({dereg_tx});
  }

  /// Register the node again
  {
    auto keys = gen.get_cached_keys(deregister_pub_key);
    cryptonote::keypair pair = {keys.pub, keys.key};
    const auto tx = gen.create_and_add_registration_tx(miner, pair);
    gen.create_and_add_next_block({tx});
  }

  /// Try to deregister the node again for heightB (should fail)
  const auto dereg_tx = gen.create_state_change_tx(gnodes::new_state::deregister, deregister_pub_key, height_b);
  gen.add_tx(dereg_tx, false /*can_be_added_to_blockchain*/, "After a Service Node has deregistered, it can NOT be deregistered from the result of a quorum preceeding the height that the Service Node re-registered as.");
  return true;

}

// Daemon A has a deregistration TX (X) in the pool. Daemon B creates a block before receiving X.
// Daemon A accepts the block without X. Now X is too old and should not be added in future blocks.
bool gyuanx_core_test_deregister_too_old::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table(cryptonote::network_version_9_gnodes);
  gyuanx_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);

  /// generate some outputs and unlock them
  gen.add_n_blocks(20);
  gen.add_mined_money_unlock_blocks();
  add_gnodes(gen, 11);

  const auto pk       = gen.top_quorum().obligations->workers[0];
  const auto dereg_tx = gen.create_and_add_state_change_tx(gnodes::new_state::deregister, pk);
  gen.add_n_blocks(gnodes::STATE_CHANGE_TX_LIFETIME_IN_BLOCKS); /// create enough blocks to make deregistrations invalid (60 blocks)

  /// In the real world, this transaction should not make it into a block, but in this case we do try to add it (as in
  /// tests we must add specify transactions manually), which should exercise the same validation code and reject the
  /// block
  gen.create_and_add_next_block({dereg_tx},
                nullptr /*checkpoint*/,
                false /*can_be_added_to_blockchain*/,
                "Trying to add a block with an old deregister sitting in the pool that was invalidated due to old age");
  return true;
}

bool gyuanx_core_test_deregister_zero_fee::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  size_t const NUM_SERVICE_NODES = 11;
  std::vector<cryptonote::transaction> reg_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    reg_txs[i] = gen.create_and_add_registration_tx(gen.first_miner_);

  gen.create_and_add_next_block(reg_txs);
  const auto deregister_pub_key = gen.top_quorum().obligations->workers[0];
  cryptonote::transaction const invalid_deregister =
      gen.create_state_change_tx(gnodes::new_state::deregister, deregister_pub_key, -1 /*height*/, {} /*voters*/, MK_COINS(1) /*fee*/);
  gen.add_tx(invalid_deregister, false /*can_be_added_to_blockchain*/, "Deregister transactions with non-zero fee can NOT be added to the blockchain");
  return true;
}

// Test a chain that is equal up to a certain point, splits, and 1 of the chains forms a block that has a deregister
// for Service Node A. Chain 2 receives a deregister for Service Node A with a different permutation of votes than
// the one known in Chain 1 and is sitting in the mempool. On reorg, Chain 2 should become the canonical chain and
// those sitting on Chain 1 should not have problems switching over.
bool gyuanx_core_test_deregister_on_split::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();
 
  add_gnodes(gen, gnodes::CHECKPOINT_QUORUM_SIZE + 1);
  gen.create_and_add_next_block(); // Can't change service node state on the same height it was registered in
  auto fork = gen;

  gen.add_event_msg("public key of the node to deregister (valid at the height of the pivot block)");
  const auto pk           = gen.top_quorum().obligations->workers[0];
  const auto split_height = gen.height();

  gen.add_event_msg("create deregistration A");
  std::vector<uint64_t> const quorum_indexes = {1, 2, 3, 4, 5, 6, 7};
  const auto dereg_a                         = gen.create_and_add_state_change_tx(gnodes::new_state::deregister, pk, split_height, quorum_indexes);

  gen.add_event_msg("create deregistration on alt chain (B)");
  std::vector<uint64_t> const fork_quorum_indexes = {1, 3, 4, 5, 6, 7, 8};
  const auto dereg_b            = fork.create_and_add_state_change_tx(gnodes::new_state::deregister, pk, split_height, fork_quorum_indexes, 0 /*fee*/, true /*kept_by_block*/);
  crypto::hash expected_tx_hash = cryptonote::get_transaction_hash(dereg_b);
  size_t dereg_index            = gen.event_index();

  gen.add_event_msg("continue main chain with deregister A");
  gen.create_and_add_next_block({dereg_a});

  fork.add_event_msg("continue alt chain with deregister B");
  gyuanx_blockchain_entry entry = fork.create_and_add_next_block({dereg_b});
  crypto::hash const expected_block_hash = cryptonote::get_block_hash(entry.block);

  fork.add_event_msg("add 2 consecutive check points to switch over");
  fork.add_blocks_until_next_checkpointable_height();
  fork.add_gnode_checkpoint(fork.height(), gnodes::CHECKPOINT_MIN_VOTES);

  fork.add_blocks_until_next_checkpointable_height();
  fork.add_gnode_checkpoint(fork.height(), gnodes::CHECKPOINT_MIN_VOTES);

  gyuanx_register_callback(events, "test_on_split", [expected_tx_hash, expected_block_hash](cryptonote::core &c, size_t ev_index)
  {
    /// Check that the deregister transaction is the one from the alternative branch
    DEFINE_TESTS_ERROR_CONTEXT("test_on_split");

    /// get the block with the deregister
    bool orphan = false;
    cryptonote::block blk;
    CHECK_TEST_CONDITION(c.get_block_by_hash(expected_block_hash, blk, &orphan));

    /// find the deregister tx:
    const auto found_tx_hash = std::find(blk.tx_hashes.begin(), blk.tx_hashes.end(), expected_tx_hash);
    CHECK_TEST_CONDITION(found_tx_hash != blk.tx_hashes.end());
    CHECK_EQ(*found_tx_hash, expected_tx_hash); /// check that it is the expected one
    return true;
  });

  return true;
}

bool gyuanx_core_test_state_change_ip_penalty_disallow_dupes::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  add_gnodes(gen, gnodes::STATE_CHANGE_QUORUM_SIZE + 1);
  gen.create_and_add_next_block(); // Can't change service node state on the same height it was registered in

  const auto pub_key                         = gen.top_quorum().obligations->workers[0];
  std::vector<uint64_t> const quorum_indexes = {1, 2, 3, 4, 5, 6, 7};
  const auto state_change_1                  = gen.create_and_add_state_change_tx(gnodes::new_state::ip_change_penalty, pub_key, gen.height(), quorum_indexes);

  // NOTE: Try duplicate state change with different quorum indexes
  {
    std::vector<uint64_t> const alt_quorum_indexes = {1, 3, 4, 5, 6, 7, 8};
    const auto state_change_2 = gen.create_state_change_tx(gnodes::new_state::ip_change_penalty, pub_key, gen.height(), alt_quorum_indexes);
    gen.add_tx(state_change_2, false /*can_be_added_to_blockchain*/, "Can't add a state change with different permutation of votes than previously submitted");

    // NOTE: Try same duplicate state change on a new height
    {
      gen.create_and_add_next_block({state_change_1});
      gen.add_tx(state_change_2, false /*can_be_added_to_blockchain*/, "Can't add a state change with different permutation of votes than previously submitted, even if the blockchain height has changed");
    }

    // NOTE: Try same duplicate state change on a new height, but set kept_by_block, i.e. this is a TX from a block on another chain
    gen.add_tx(state_change_2, true /*can_be_added_to_blockchain*/, "We should be able to accept dupe ip changes if TX is kept by block (i.e. from alt chain) otherwise we can never reorg to that chain", true /*kept_by_block*/);
  }

  return true;
}

static bool verify_lns_mapping_record(char const *perr_context,
                                      lns::mapping_record const &record,
                                      lns::mapping_type type,
                                      std::string const &name,
                                      lns::mapping_value const &value,
                                      uint64_t update_height,
                                      std::optional<uint64_t> expiration_height,
                                      crypto::hash const &txid,
                                      lns::generic_owner const &owner,
                                      lns::generic_owner const &backup_owner)
{
  CHECK_EQ(record.loaded,          true);
  CHECK_EQ(record.type,            type);
  auto lcname = tools::lowercase_ascii_string(name);
  CHECK_EQ(record.name_hash,       lns::name_to_base64_hash(lcname));
  lns::mapping_value decrypted{record.encrypted_value};
  CHECK_EQ(decrypted.decrypt(lcname, type), true);
  CHECK_EQ(decrypted, value);
  CHECK_EQ(record.update_height,   update_height);
  CHECK_EQ(record.expiration_height.has_value(), expiration_height.has_value());
  if (expiration_height)
    CHECK_EQ(*record.expiration_height, *expiration_height);
  CHECK_EQ(record.txid,            txid);
  CHECK_TEST_CONDITION_MSG(record.owner == owner, record.owner.to_string(cryptonote::FAKECHAIN) << " == "<< owner.to_string(cryptonote::FAKECHAIN));
  CHECK_TEST_CONDITION_MSG(record.backup_owner == backup_owner, record.backup_owner.to_string(cryptonote::FAKECHAIN) << " == "<< backup_owner.to_string(cryptonote::FAKECHAIN));
  return true;
}

bool gyuanx_name_system_disallow_reserved_type::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  lns::mapping_value mapping_value = {};
  mapping_value.len                = 20;

  auto unusable_type = static_cast<lns::mapping_type>(-1);
  assert(!lns::mapping_type_allowed(gen.hardfork(), unusable_type));
  cryptonote::transaction tx1 = gen.create_gyuanx_name_system_tx(miner, gen.hardfork(), unusable_type, "FriendlyName", mapping_value);
  gen.add_tx(tx1, false /*can_be_added_to_blockchain*/, "Can't create a LNS TX that requests a LNS type that is unused but reserved by the protocol");
  return true;
}

struct lns_keys_t
{
  lns::generic_owner owner;
  lns::mapping_value wallet_value; // NOTE: this field is the binary (value) part of the name -> (value) mapping
  lns::mapping_value gyuanxnet_value;
  lns::mapping_value session_value;
};

static lns_keys_t make_lns_keys(cryptonote::account_base const &src)
{
  lns_keys_t result             = {};
  result.owner                  = lns::make_monero_owner(src.get_keys().m_account_address, false /*is_subaddress*/);
  result.session_value.len      = lns::SESSION_PUBLIC_KEY_BINARY_LENGTH;
  result.wallet_value.len       = sizeof(src.get_keys().m_account_address);
  result.gyuanxnet_value.len      = sizeof(result.owner.wallet.address.m_spend_public_key);

  memcpy(&result.session_value.buffer[0] + 1, &result.owner.wallet.address.m_spend_public_key, result.gyuanxnet_value.len);
  memcpy(&result.wallet_value.buffer[0], (char *)&src.get_keys().m_account_address, result.wallet_value.len);

  // NOTE: Just needs a 32 byte key. Reuse spend key
  memcpy(&result.gyuanxnet_value.buffer[0], (char *)&result.owner.wallet.address.m_spend_public_key, result.gyuanxnet_value.len);

  result.session_value.buffer[0] = 5; // prefix with 0x05
  return result;
}

// Gyuanxnet FAKECHAIN LNS expiry blocks
uint64_t gyuanxnet_expiry(lns::mapping_type type) {
  auto exp = lns::expiry_blocks(cryptonote::FAKECHAIN, type);
  if (!exp) throw std::logic_error{"test suite bug: gyuanxnet_expiry called with non-gyuanxnet mapping type"};
  return *exp;
}

bool gyuanx_name_system_expiration::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);
  cryptonote::account_base miner = gen.first_miner_;

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  lns_keys_t miner_key = make_lns_keys(miner);
  for (auto mapping_type = lns::mapping_type::gyuanxnet;
       mapping_type     <= lns::mapping_type::gyuanxnet_10years;
       mapping_type      = static_cast<lns::mapping_type>(static_cast<uint16_t>(mapping_type) + 1))
  {
    std::string const name     = "mydomain.gyuanx";
    if (lns::mapping_type_allowed(gen.hardfork(), mapping_type))
    {
      cryptonote::transaction tx = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), mapping_type, name, miner_key.gyuanxnet_value);
      gen.create_and_add_next_block({tx});
      crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);

      uint64_t height_of_lns_entry   = gen.height();
      uint64_t expected_expiry_block = height_of_lns_entry + gyuanxnet_expiry(mapping_type);
      std::string name_hash = lns::name_to_base64_hash(name);

      gyuanx_register_callback(events, "check_lns_entries", [=](cryptonote::core &c, size_t ev_index)
      {
        DEFINE_TESTS_ERROR_CONTEXT("check_lns_entries");
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
        CHECK_EQ(owner.loaded, true);
        CHECK_EQ(owner.id, 1);
        CHECK_TEST_CONDITION_MSG(miner_key.owner == owner.address,
                                 miner_key.owner.to_string(cryptonote::FAKECHAIN)
                                     << " == " << owner.address.to_string(cryptonote::FAKECHAIN));

        lns::mapping_record record = lns_db.get_mapping(mapping_type, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::gyuanxnet, name, miner_key.gyuanxnet_value, height_of_lns_entry, height_of_lns_entry + gyuanxnet_expiry(mapping_type), tx_hash, miner_key.owner, {} /*backup_owner*/));
        return true;
      });

      while (gen.height() <= expected_expiry_block)
        gen.create_and_add_next_block();

      gyuanx_register_callback(events, "check_expired", [=, blockchain_height = gen.chain_height()](cryptonote::core &c, size_t ev_index)
      {
        DEFINE_TESTS_ERROR_CONTEXT("check_expired");
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

        // TODO(gyuanx): We should probably expire owners that no longer have any mappings remaining
        lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
        CHECK_EQ(owner.loaded, true);
        CHECK_EQ(owner.id, 1);
        CHECK_TEST_CONDITION_MSG(miner_key.owner == owner.address,
                                 miner_key.owner.to_string(cryptonote::FAKECHAIN)
                                     << " == " << owner.address.to_string(cryptonote::FAKECHAIN));

        lns::mapping_record record = lns_db.get_mapping(mapping_type, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::gyuanxnet, name, miner_key.gyuanxnet_value, height_of_lns_entry, height_of_lns_entry + gyuanxnet_expiry(mapping_type), tx_hash, miner_key.owner, {} /*backup_owner*/));
        CHECK_EQ(record.active(blockchain_height), false);
        return true;
      });
    }
    else
    {
      cryptonote::transaction tx = gen.create_gyuanx_name_system_tx(miner, gen.hardfork(), mapping_type, name, miner_key.gyuanxnet_value);
      gen.add_tx(tx, false /*can_be_added_to_blockchain*/, "Can not add LNS TX that uses disallowed type");
    }
  }
  return true;
}

bool gyuanx_name_system_get_mappings_by_owner::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  cryptonote::account_base bob   = gen.add_account();
  gen.add_blocks_until_version(hard_forks.back().first);

  // NOTE: Fund Bob's wallet
  {
    gen.add_mined_money_unlock_blocks();

    // Chop this transfer into multiple txes because we need enough inputs to send multiple txes at once below.
    std::vector<cryptonote::transaction> txs;
    txs.reserve(6);
    for (int i = 0; i < 6; i++)
      txs.push_back(gen.create_and_add_tx(miner, bob.get_keys().m_account_address, MK_COINS(100)));
    gen.create_and_add_next_block(std::move(txs));
    gen.add_transfer_unlock_blocks();
  }

  lns_keys_t bob_key = make_lns_keys(bob);
  // NB: we sort the results later by (height, name hash), so our test values need to be in sorted order:
  std::string session_name1       = "AnotherName";
  std::string session_name_hash1  = "Dw4l4Qtc8plvIoVDpE7LjigVVEkjfl6CGiLIZJ0A+pE=";
  std::string session_name2       = "MyName";
  std::string session_name_hash2  = "pwlWkoJq8LXb6Y2ILlCXNvfyBQBt71XWz3c7rkt6myM=";
  crypto::hash session_name1_txid = {}, session_name2_txid = {};
  {
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(bob, gen.hardfork(), lns::mapping_type::session, session_name1, bob_key.session_value);
    cryptonote::transaction tx2 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::session, session_name2, bob_key.session_value, &bob_key.owner);
    gen.create_and_add_next_block({tx1, tx2});
    session_name1_txid = get_transaction_hash(tx1);
    session_name2_txid = get_transaction_hash(tx2);
  }
  uint64_t session_height = gen.height();

  // NOTE: Register some Gyuanxnet names
  std::string gyuanxnet_name1 = "Lorem.gyuanx";
  std::string gyuanxnet_name_hash1 = "GsM6OUk5E5D9keBIK2PlA4kjwiPe+/UB0nUurjKvFJQ=";
  std::string gyuanxnet_name2 = "ipSum.gyuanx";
  std::string gyuanxnet_name_hash2 = "p8IYR3ZWr0KSU4ZPazYxTkwvXsm0dzq5dmour7VmIDY=";
  crypto::hash gyuanxnet_name1_txid = {}, gyuanxnet_name2_txid = {};
  if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::gyuanxnet))
  {
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(bob, gen.hardfork(), lns::mapping_type::gyuanxnet, gyuanxnet_name1, bob_key.gyuanxnet_value);
    cryptonote::transaction tx2 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::gyuanxnet_5years, gyuanxnet_name2, bob_key.gyuanxnet_value, &bob_key.owner);
    gen.create_and_add_next_block({tx1, tx2});
    gyuanxnet_name1_txid = get_transaction_hash(tx1);
    gyuanxnet_name2_txid = get_transaction_hash(tx2);
  }
  uint64_t gyuanxnet_height = gen.height();

  // NOTE: Register some wallet names
  std::string wallet_name1 = "Wallet1";
  std::string wallet_name_hash1 = "2dRJORvkHcT6Ns8mXprzgiZ26v7OT7FhiMo+DMB3Myw=";
  std::string wallet_name2 = "Wallet2";
  std::string wallet_name_hash2 = "634Je6csR8w9a8vj/DEOIb1E1qk/ZmZF9DXSlh/p0zI=";
  crypto::hash wallet_name1_txid = {}, wallet_name2_txid = {};
  if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::wallet))
  {
    std::string bob_addr = cryptonote::get_account_address_as_str(cryptonote::FAKECHAIN, false, bob.get_keys().m_account_address);
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(bob, gen.hardfork(), lns::mapping_type::wallet, wallet_name1, bob_key.wallet_value);
    cryptonote::transaction tx2 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::wallet, wallet_name2, bob_key.wallet_value, &bob_key.owner);
    gen.create_and_add_next_block({tx1, tx2});
    wallet_name1_txid = get_transaction_hash(tx1);
    wallet_name2_txid = get_transaction_hash(tx2);
  }
  uint64_t wallet_height = gen.height();

  gyuanx_register_callback(events, "check_lns_entries", [=](cryptonote::core &c, size_t ev_index)
  {
    const char* perr_context = "check_lns_entries";
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
    std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(bob_key.owner);

    size_t expected_size = 0;
    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::session)) expected_size += 2;
    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::wallet)) expected_size += 2;
    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::gyuanxnet)) expected_size += 2;
    CHECK_EQ(records.size(), expected_size);

    std::sort(records.begin(), records.end(), [](const auto& a, const auto& b) {
      return std::make_tuple(a.update_height, a.name_hash)
           < std::make_tuple(b.update_height, b.name_hash);
    });

    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::session))
    {
      CHECK_EQ(records[0].name_hash, session_name_hash1);
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[0], lns::mapping_type::session, session_name1, bob_key.session_value, session_height, std::nullopt, session_name1_txid, bob_key.owner, {} /*backup_owner*/));
      CHECK_EQ(records[1].name_hash, session_name_hash2);
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[1], lns::mapping_type::session, session_name2, bob_key.session_value, session_height, std::nullopt, session_name2_txid, bob_key.owner, {} /*backup_owner*/));
    }

    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::gyuanxnet))
    {
      CHECK_EQ(records[2].name_hash, gyuanxnet_name_hash1);
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[2], lns::mapping_type::gyuanxnet, gyuanxnet_name1, bob_key.gyuanxnet_value, gyuanxnet_height, gyuanxnet_height + gyuanxnet_expiry(lns::mapping_type::gyuanxnet), gyuanxnet_name1_txid, bob_key.owner, {} /*backup_owner*/));
      CHECK_EQ(records[3].name_hash, gyuanxnet_name_hash2);
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[3], lns::mapping_type::gyuanxnet, gyuanxnet_name2, bob_key.gyuanxnet_value, gyuanxnet_height, gyuanxnet_height + gyuanxnet_expiry(lns::mapping_type::gyuanxnet_5years), gyuanxnet_name2_txid, bob_key.owner, {} /*backup_owner*/));
    }

    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::wallet))
    {
      CHECK_EQ(records[4].name_hash, wallet_name_hash1);
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[4], lns::mapping_type::wallet, wallet_name1, bob_key.wallet_value, wallet_height, std::nullopt, wallet_name1_txid, bob_key.owner, {} /*backup_owner*/));
      CHECK_EQ(records[5].name_hash, wallet_name_hash2);
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[5], lns::mapping_type::wallet, wallet_name2, bob_key.wallet_value, wallet_height, std::nullopt, wallet_name2_txid, bob_key.owner, {} /*backup_owner*/));
    }
    return true;
  });

  return true;
}

bool gyuanx_name_system_get_mappings_by_owners::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  cryptonote::account_base bob   = gen.add_account();
  gen.add_blocks_until_version(hard_forks.back().first);

  // NOTE: Fund Bob's wallet
  {
    gen.add_mined_money_unlock_blocks();
    cryptonote::transaction transfer = gen.create_and_add_tx(miner, bob.get_keys().m_account_address, MK_COINS(400));
    gen.create_and_add_next_block({transfer});
    gen.add_transfer_unlock_blocks();
  }

  lns_keys_t bob_key   = make_lns_keys(bob);
  lns_keys_t miner_key = make_lns_keys(miner);

  std::string session_name1 = "MyName";
  crypto::hash session_tx_hash1;
  {
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(bob, gen.hardfork(), lns::mapping_type::session, session_name1, bob_key.session_value);
    session_tx_hash1 = cryptonote::get_transaction_hash(tx1);
    gen.create_and_add_next_block({tx1});
  }
  uint64_t session_height1 = gen.height();
  gen.add_n_blocks(10);

  std::string session_name2 = "MyName2";
  crypto::hash session_tx_hash2;
  {
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(bob, gen.hardfork(), lns::mapping_type::session, session_name2, bob_key.session_value);
    session_tx_hash2 = cryptonote::get_transaction_hash(tx1);
    gen.create_and_add_next_block({tx1});
  }
  uint64_t session_height2 = gen.height();
  gen.add_n_blocks(10);

  std::string session_name3 = "MyName3";
  crypto::hash session_tx_hash3;
  {
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::session, session_name3, miner_key.session_value);
    session_tx_hash3 = cryptonote::get_transaction_hash(tx1);
    gen.create_and_add_next_block({tx1});
  }
  uint64_t session_height3 = gen.height();
  gen.add_n_blocks(10);

  gyuanx_register_callback(events, "check_lns_entries", [=](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_lns_entries");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
    std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owners({bob_key.owner, miner_key.owner});
    CHECK_EQ(records.size(), 3);
    std::sort(records.begin(), records.end(), [](lns::mapping_record const &lhs, lns::mapping_record const &rhs) {
      return lhs.update_height < rhs.update_height;
    });

    int index = 0;
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[index++], lns::mapping_type::session, session_name1, bob_key.session_value, session_height1, std::nullopt, session_tx_hash1, bob_key.owner, {}));
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[index++], lns::mapping_type::session, session_name2, bob_key.session_value, session_height2, std::nullopt, session_tx_hash2, bob_key.owner, {}));
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[index++], lns::mapping_type::session, session_name3, miner_key.session_value, session_height3, std::nullopt, session_tx_hash3, miner_key.owner, {}));
    return true;
  });

  return true;
}

bool gyuanx_name_system_get_mappings::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  cryptonote::account_base bob   = gen.add_account();
  gen.add_blocks_until_version(hard_forks.back().first);

  // NOTE: Fund Bob's wallet
  {
    gen.add_mined_money_unlock_blocks();

    cryptonote::transaction transfer = gen.create_and_add_tx(miner, bob.get_keys().m_account_address, MK_COINS(400));
    gen.create_and_add_next_block({transfer});
    gen.add_transfer_unlock_blocks();
  }

  lns_keys_t bob_key = make_lns_keys(bob);
  std::string session_name1 = "MyName";
  crypto::hash session_tx_hash;
  {
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(bob, gen.hardfork(), lns::mapping_type::session, session_name1, bob_key.session_value);
    session_tx_hash = cryptonote::get_transaction_hash(tx1);
    gen.create_and_add_next_block({tx1});
  }
  uint64_t session_height = gen.height();

  gyuanx_register_callback(events, "check_lns_entries", [bob_key, session_height, session_name1, session_tx_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_lns_entries");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
    std::string session_name_hash = lns::name_to_base64_hash(tools::lowercase_ascii_string(session_name1));
    std::vector<lns::mapping_record> records = lns_db.get_mappings({lns::mapping_type::session}, session_name_hash);
    CHECK_EQ(records.size(), 1);
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[0], lns::mapping_type::session, session_name1, bob_key.session_value, session_height, std::nullopt, session_tx_hash, bob_key.owner, {} /*backup_owner*/));
    return true;
  });

  return true;
}

bool gyuanx_name_system_handles_duplicate_in_lns_db::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  cryptonote::account_base bob   = gen.add_account();

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  cryptonote::transaction transfer = gen.create_and_add_tx(miner, bob.get_keys().m_account_address, MK_COINS(400));
  gen.create_and_add_next_block({transfer});
  gen.add_transfer_unlock_blocks();

  lns_keys_t miner_key     = make_lns_keys(miner);
  lns_keys_t bob_key       = make_lns_keys(bob);
  std::string session_name = "myfriendlydisplayname.gyuanx";
  std::string gyuanxnet_name = session_name;
  auto custom_type         = static_cast<lns::mapping_type>(3928);
  crypto::hash session_tx_hash = {}, gyuanxnet_tx_hash = {};
  {
    // NOTE: Allow duplicates with the same name but different type
    cryptonote::transaction bar = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::session, session_name, bob_key.session_value);
    session_tx_hash = get_transaction_hash(bar);

    std::vector<cryptonote::transaction> txs;
    txs.push_back(bar);

    if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::gyuanxnet))
    {
      cryptonote::transaction bar3 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::gyuanxnet_2years, session_name, miner_key.gyuanxnet_value);
      txs.push_back(bar3);
      gyuanxnet_tx_hash = get_transaction_hash(bar3);
    }

    gen.create_and_add_next_block(txs);
  }
  uint64_t height_of_lns_entry = gen.height();

  {
    cryptonote::transaction bar6 = gen.create_gyuanx_name_system_tx(bob, gen.hardfork(), lns::mapping_type::session, session_name, bob_key.session_value);
    gen.add_tx(bar6, false /*can_be_added_to_blockchain*/, "Duplicate name requested by new owner: original already exists in lns db");
  }

  gyuanx_register_callback(events, "check_lns_entries", [=, blockchain_height=gen.chain_height()](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_lns_entries");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

    lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
    CHECK_EQ(owner.loaded, true);
    CHECK_EQ(owner.id, 1);
    CHECK_TEST_CONDITION_MSG(miner_key.owner == owner.address,
                             miner_key.owner.to_string(cryptonote::FAKECHAIN)
                                 << " == " << owner.address.to_string(cryptonote::FAKECHAIN));

    std::string session_name_hash = lns::name_to_base64_hash(session_name);
    lns::mapping_record record1 = lns_db.get_mapping(lns::mapping_type::session, session_name_hash);
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record1, lns::mapping_type::session, session_name, bob_key.session_value, height_of_lns_entry, std::nullopt, session_tx_hash, miner_key.owner, {} /*backup_owner*/));
    CHECK_EQ(record1.owner_id, owner.id);

    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::gyuanxnet))
    {
      lns::mapping_record record2 = lns_db.get_mapping(lns::mapping_type::gyuanxnet, session_name_hash);
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record2, lns::mapping_type::gyuanxnet, gyuanxnet_name, miner_key.gyuanxnet_value, height_of_lns_entry, height_of_lns_entry + gyuanxnet_expiry(lns::mapping_type::gyuanxnet_2years), gyuanxnet_tx_hash, miner_key.owner, {} /*backup_owner*/));
      CHECK_EQ(record2.owner_id, owner.id);
      CHECK_EQ(record2.active(blockchain_height), true);
    }

    lns::owner_record owner2 = lns_db.get_owner_by_key(bob_key.owner);
    CHECK_EQ(owner2.loaded, false);
    return true;
  });
  return true;
}

bool gyuanx_name_system_handles_duplicate_in_tx_pool::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  cryptonote::account_base bob   = gen.add_account();
  {
    gen.add_blocks_until_version(hard_forks.back().first);
    gen.add_mined_money_unlock_blocks();

    cryptonote::transaction transfer = gen.create_and_add_tx(miner, bob.get_keys().m_account_address, MK_COINS(400));
    gen.create_and_add_next_block({transfer});
    gen.add_transfer_unlock_blocks();
  }

  lns_keys_t bob_key       = make_lns_keys(bob);
  std::string session_name = "myfriendlydisplayname.gyuanx";

  auto custom_type = static_cast<lns::mapping_type>(3928);
  {
    // NOTE: Allow duplicates with the same name but different type
    cryptonote::transaction bar = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::session, session_name, bob_key.session_value);

    if (lns::mapping_type_allowed(gen.hardfork(), custom_type))
      cryptonote::transaction bar2 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), custom_type, session_name, bob_key.session_value);

    // NOTE: Make duplicate in the TX pool, this should be rejected
    cryptonote::transaction bar4 = gen.create_gyuanx_name_system_tx(bob, gen.hardfork(), lns::mapping_type::session, session_name, bob_key.session_value);
    gen.add_tx(bar4, false /*can_be_added_to_blockchain*/, "Duplicate name requested by new owner: original already exists in tx pool");
  }
  return true;
}

bool gyuanx_name_system_invalid_tx_extra_params::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  lns_keys_t miner_key = make_lns_keys(miner);
  // Manually construct transaction with invalid tx extra
  {
    auto make_lns_tx_with_custom_extra = [&](gyuanx_chain_generator &gen,
                                             std::vector<test_event_entry> &events,
                                             cryptonote::account_base const &src,
                                             cryptonote::tx_extra_gyuanx_name_system &data,
                                             bool valid,
                                             char const *reason) -> void {
      uint64_t new_height    = cryptonote::get_block_height(gen.top().block) + 1;
      uint8_t new_hf_version = gen.get_hf_version_at(new_height);
      uint64_t burn_requirement = lns::burn_needed(new_hf_version, static_cast<lns::mapping_type>(data.type));

      std::vector<uint8_t> extra;
      cryptonote::add_gyuanx_name_system_to_tx_extra(extra, data);
      cryptonote::add_burned_amount_to_tx_extra(extra, burn_requirement);

      cryptonote::transaction tx = {};
      gyuanx_tx_builder(events, tx, gen.top().block, src /*from*/, src.get_keys().m_account_address, 0, new_hf_version)
          .with_tx_type(cryptonote::txtype::gyuanx_name_system)
          .with_extra(extra)
          .with_fee(burn_requirement + TESTS_DEFAULT_FEE)
          .build();

      gen.add_tx(tx, valid /*can_be_added_to_blockchain*/, reason, false /*kept_by_block*/);
    };

    std::string name = "my_lns_name";
    cryptonote::tx_extra_gyuanx_name_system valid_data = {};
    valid_data.fields |= lns::extra_field::buy_no_backup;
    valid_data.owner = miner_key.owner;
    valid_data.type  = lns::mapping_type::wallet;
    valid_data.encrypted_value = miner_key.wallet_value.make_encrypted(name).to_string();
    valid_data.name_hash       = lns::name_to_hash(name);

    if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::wallet))
    {
      valid_data.type = lns::mapping_type::wallet;
      // Blockchain name empty
      {
        cryptonote::tx_extra_gyuanx_name_system data = valid_data;
        data.name_hash                             = {};
        data.encrypted_value                       = miner_key.wallet_value.make_encrypted("").to_string();
        make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Blockchain) Empty wallet name in LNS is invalid");
      }

      // Blockchain value (wallet address) is invalid, too short
      {
        cryptonote::tx_extra_gyuanx_name_system data = valid_data;
        data.encrypted_value                       = miner_key.wallet_value.make_encrypted(name).to_string();
        data.encrypted_value.resize(data.encrypted_value.size() - 1);
        make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Blockchain) Wallet value in LNS too long");
      }

      // Blockchain value (wallet address) is invalid, too long
      {
        cryptonote::tx_extra_gyuanx_name_system data = valid_data;
        data.encrypted_value                       = miner_key.wallet_value.make_encrypted(name).to_string();
        data.encrypted_value.resize(data.encrypted_value.size() + 1);
        make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Blockchain) Wallet value in LNS too long");
      }
    }

    if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::gyuanxnet))
    {
      valid_data.type = lns::mapping_type::gyuanxnet;
      // Gyuanxnet name empty
      {
        cryptonote::tx_extra_gyuanx_name_system data = valid_data;
        data.name_hash                             = {};
        data.encrypted_value                       = miner_key.gyuanxnet_value.make_encrypted("").to_string();
        make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Gyuanxnet) Empty domain name in LNS is invalid");
      }

      // Gyuanxnet value too short
      {
        cryptonote::tx_extra_gyuanx_name_system data = valid_data;
        data.encrypted_value                       = miner_key.gyuanxnet_value.make_encrypted(name).to_string();
        data.encrypted_value.resize(data.encrypted_value.size() - 1);
        make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Gyuanxnet) Domain value in LNS too long");
      }

      // Gyuanxnet value too long
      {
        cryptonote::tx_extra_gyuanx_name_system data = valid_data;
        data.encrypted_value                       = miner_key.gyuanxnet_value.make_encrypted(name).to_string();
        data.encrypted_value.resize(data.encrypted_value.size() + 1);
        make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Gyuanxnet) Domain value in LNS too long");
      }
    }

    // Session value too short
    // We added valid tx prior, we should update name to avoid conflict names in session land and test other invalid params
    valid_data.type      = lns::mapping_type::session;
    name                 = "new_friendly_name";
    valid_data.name_hash = lns::name_to_hash(name);
    {
      cryptonote::tx_extra_gyuanx_name_system data = valid_data;
      data.encrypted_value                       = miner_key.session_value.make_encrypted(name).to_string();
      data.encrypted_value.resize(data.encrypted_value.size() - 1);
      make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Session) User id, value too short");
    }

    // Session value too long
    {
      cryptonote::tx_extra_gyuanx_name_system data = valid_data;
      data.encrypted_value                       = miner_key.session_value.make_encrypted(name).to_string();
      data.encrypted_value.resize(data.encrypted_value.size() + 1);
      make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Session) User id, value too long");
    }

    // Session name empty
    {
      cryptonote::tx_extra_gyuanx_name_system data = valid_data;
      data.name_hash                             = {};
      data.encrypted_value                       = miner_key.session_value.make_encrypted("").to_string();
      make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Session) Name empty");
    }
  }
  return true;
}

bool gyuanx_name_system_large_reorg::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  cryptonote::account_base const miner = gen.first_miner_;
  cryptonote::account_base const bob   = gen.add_account();
  lns_keys_t const miner_key           = make_lns_keys(miner);
  lns_keys_t const bob_key             = make_lns_keys(bob);
  {
    gen.add_blocks_until_version(hard_forks.back().first);
    gen.add_mined_money_unlock_blocks();

    cryptonote::transaction transfer = gen.create_and_add_tx(miner, bob.get_keys().m_account_address, MK_COINS(400));
    gen.create_and_add_next_block({transfer});
    gen.add_transfer_unlock_blocks();
  }

  // NOTE: Generate the first round of LNS transactions belonging to miner
  uint64_t first_lns_height                 = 0;
  std::string const gyuanxnet_name1           = "website.gyuanx";
  std::string const wallet_name1            = "MyWallet";
  std::string const session_name1           = "I-Like-Gyuanx";
  crypto::hash session_tx_hash1 = {}, wallet_tx_hash1 = {}, gyuanxnet_tx_hash1 = {};
  {
    // NOTE: Generate and add the (transactions + block) to the blockchain
    {
      std::vector<cryptonote::transaction> txs;
      cryptonote::transaction session_tx = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::session, session_name1, miner_key.session_value);
      session_tx_hash1 = get_transaction_hash(session_tx);
      txs.push_back(session_tx);

      if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::wallet))
      {
        cryptonote::transaction wallet_tx = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::wallet, wallet_name1, miner_key.wallet_value);
        txs.push_back(wallet_tx);
        wallet_tx_hash1 = get_transaction_hash(wallet_tx);
      }

      if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::gyuanxnet_10years))
      {
        cryptonote::transaction gyuanxnet_tx = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::gyuanxnet_10years, gyuanxnet_name1, miner_key.gyuanxnet_value);
        txs.push_back(gyuanxnet_tx);
        gyuanxnet_tx_hash1 = get_transaction_hash(gyuanxnet_tx);
      }
      gen.create_and_add_next_block(txs);
    }
    first_lns_height = gen.height();

    gyuanx_register_callback(events, "check_first_lns_entries", [=](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_first_lns_entries");
      lns::name_system_db &lns_db        = c.get_blockchain_storage().name_system_db();
      std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(miner_key.owner);
      CHECK_EQ(lns_db.height(), first_lns_height);

      size_t expected_size = 1;
      if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::wallet)) expected_size += 1;
      if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::gyuanxnet)) expected_size += 1;
      CHECK_EQ(records.size(), expected_size);

      for (lns::mapping_record const &record : records)
      {
        if (record.type == lns::mapping_type::session)
          CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, session_name1, miner_key.session_value, first_lns_height, std::nullopt, session_tx_hash1, miner_key.owner, {} /*backup_owner*/));
        else if (record.type == lns::mapping_type::gyuanxnet)
          CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::gyuanxnet, gyuanxnet_name1, miner_key.gyuanxnet_value, first_lns_height, first_lns_height + gyuanxnet_expiry(lns::mapping_type::gyuanxnet_10years), gyuanxnet_tx_hash1, miner_key.owner, {} /*backup_owner*/));
        else if (record.type == lns::mapping_type::wallet)
          CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::wallet, wallet_name1, miner_key.wallet_value, first_lns_height, std::nullopt, wallet_tx_hash1, miner_key.owner, {} /*backup_owner*/));
        else
        {
          assert(false);
        }
      }
      return true;
    });
  }

  // NOTE: Generate and add the second round of (transactions + block) to the blockchain, renew gyuanxnet and add bob's session, update miner's session value to other's session value
  cryptonote::account_base const other = gen.add_account();
  lns_keys_t const other_key           = make_lns_keys(other);
  uint64_t second_lns_height = 0;
  {
    std::string const bob_session_name1 = "I-Like-Session";
    crypto::hash session_tx_hash2 = {}, gyuanxnet_tx_hash2 = {}, session_tx_hash3;
    {
      std::vector<cryptonote::transaction> txs;
      txs.push_back(gen.create_and_add_gyuanx_name_system_tx(bob, gen.hardfork(), lns::mapping_type::session, bob_session_name1, bob_key.session_value));
      session_tx_hash2 = cryptonote::get_transaction_hash(txs[0]);

      if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::gyuanxnet))
      {
        txs.push_back(gen.create_and_add_gyuanx_name_system_tx_renew(miner, gen.hardfork(), lns::mapping_type::gyuanxnet_5years, gyuanxnet_name1));
        gyuanxnet_tx_hash2 = cryptonote::get_transaction_hash(txs.back());
      }

      txs.push_back(gen.create_and_add_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, session_name1, &other_key.session_value));
      session_tx_hash3 = cryptonote::get_transaction_hash(txs.back());

      gen.create_and_add_next_block(txs);
    }
    second_lns_height = gen.height();

    gyuanx_register_callback(events, "check_second_lns_entries", [=](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_second_lns_entries");
      lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
      CHECK_EQ(lns_db.height(), second_lns_height);

      // NOTE: Check miner's record
      {
        std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(miner_key.owner);
        for (lns::mapping_record const &record : records)
        {
          if (record.type == lns::mapping_type::session)
            CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, session_name1, other_key.session_value, second_lns_height, std::nullopt, session_tx_hash3, miner_key.owner, {} /*backup_owner*/));
          else if (record.type == lns::mapping_type::gyuanxnet)
            CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::gyuanxnet, gyuanxnet_name1, miner_key.gyuanxnet_value, second_lns_height, first_lns_height + gyuanxnet_expiry(lns::mapping_type::gyuanxnet_5years) + gyuanxnet_expiry(lns::mapping_type::gyuanxnet_10years), gyuanxnet_tx_hash2, miner_key.owner, {} /*backup_owner*/));
          else if (record.type == lns::mapping_type::wallet)
            CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::wallet, wallet_name1, miner_key.wallet_value, first_lns_height, std::nullopt, wallet_tx_hash1, miner_key.owner, {} /*backup_owner*/));
          else
          {
            assert(false);
          }
        }
      }

      // NOTE: Check bob's records
      {
        std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(bob_key.owner);
        CHECK_EQ(records.size(), 1);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[0], lns::mapping_type::session, bob_session_name1, bob_key.session_value, second_lns_height, std::nullopt, session_tx_hash2, bob_key.owner, {} /*backup_owner*/));
      }

      return true;
    });
  }

  gyuanx_register_callback(events, "trigger_blockchain_detach", [=](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("trigger_blockchain_detach");
    cryptonote::Blockchain &blockchain = c.get_blockchain_storage();

    // NOTE: Reorg to just before the 2nd round of LNS entries
    uint64_t curr_height   = blockchain.get_current_blockchain_height();
    uint64_t blocks_to_pop = curr_height - second_lns_height;
    blockchain.pop_blocks(blocks_to_pop);
    lns::name_system_db &lns_db  = blockchain.name_system_db();
    CHECK_EQ(lns_db.height(), blockchain.get_current_blockchain_height() - 1);

    // NOTE: Check bob's records got removed due to popping back to before it existed
    {
      std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(bob_key.owner);
      CHECK_EQ(records.size(), 0);

      lns::owner_record owner = lns_db.get_owner_by_key(bob_key.owner);
      CHECK_EQ(owner.loaded, false);
    }

    // NOTE: Check miner's records reverted
    {
      std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(miner_key.owner);
      size_t expected_size = 1;
      if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::wallet)) expected_size += 1;
      if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::gyuanxnet)) expected_size += 1;
      CHECK_EQ(records.size(), expected_size);

      for (lns::mapping_record const &record : records)
      {
        if (record.type == lns::mapping_type::session)
          CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, session_name1, miner_key.session_value, first_lns_height, std::nullopt, session_tx_hash1, miner_key.owner, {} /*backup_owner*/));
        else if (record.type == lns::mapping_type::gyuanxnet)
          CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::gyuanxnet, gyuanxnet_name1, miner_key.gyuanxnet_value, first_lns_height, first_lns_height + gyuanxnet_expiry(lns::mapping_type::gyuanxnet_10years), gyuanxnet_tx_hash1, miner_key.owner, {} /*backup_owner*/));
        else if (record.type == lns::mapping_type::wallet)
          CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::wallet, wallet_name1, miner_key.wallet_value, first_lns_height, std::nullopt, wallet_tx_hash1, miner_key.owner, {} /*backup_owner*/));
        else
        {
          assert(false);
        }
      }
    }

    return true;
  });

  gyuanx_register_callback(events, "trigger_blockchain_detach_all_records_gone", [miner_key, first_lns_height](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_second_lns_entries");
    cryptonote::Blockchain &blockchain = c.get_blockchain_storage();

    // NOTE: Reorg to just before the 2nd round of LNS entries
    uint64_t curr_height   = blockchain.get_current_blockchain_height();
    uint64_t blocks_to_pop = curr_height - first_lns_height;
    blockchain.pop_blocks(blocks_to_pop);
    lns::name_system_db &lns_db  = blockchain.name_system_db();
    CHECK_EQ(lns_db.height(), blockchain.get_current_blockchain_height() - 1);

    // NOTE: Check miner's records are gone
    {
      std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(miner_key.owner);
      CHECK_EQ(records.size(), 0);

      lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
      CHECK_EQ(owner.loaded, false);
    }
    return true;
  });
  return true;
}

bool gyuanx_name_system_name_renewal::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);
  cryptonote::account_base miner = gen.first_miner_;

  if (!lns::mapping_type_allowed(hard_forks.back().first, lns::mapping_type::gyuanxnet))
      return true;

  {
    gen.add_blocks_until_version(hard_forks.back().first);
    gen.add_mined_money_unlock_blocks();
  }

  lns_keys_t miner_key = make_lns_keys(miner);
  std::string const name    = "mydomain.gyuanx";
  cryptonote::transaction tx = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::gyuanxnet, name, miner_key.gyuanxnet_value);
  gen.create_and_add_next_block({tx});
  crypto::hash prev_txid = get_transaction_hash(tx);

  uint64_t height_of_lns_entry = gen.height();

  gyuanx_register_callback(events, "check_lns_entries", [=](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_lns_entries");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

    lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
    CHECK_EQ(owner.loaded, true);
    CHECK_EQ(owner.id, 1);
    CHECK_TEST_CONDITION_MSG(miner_key.owner == owner.address,
                             miner_key.owner.to_string(cryptonote::FAKECHAIN)
                                 << " == " << owner.address.to_string(cryptonote::FAKECHAIN));

    std::string name_hash = lns::name_to_base64_hash(name);
    lns::mapping_record record = lns_db.get_mapping(lns::mapping_type::gyuanxnet, name_hash);
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::gyuanxnet, name, miner_key.gyuanxnet_value, height_of_lns_entry, height_of_lns_entry + gyuanxnet_expiry(lns::mapping_type::gyuanxnet), prev_txid, miner_key.owner, {} /*backup_owner*/));
    return true;
  });

  gen.create_and_add_next_block();

  // Renew the gyuanxnet entry a few times
  cryptonote::transaction renew_tx = gen.create_and_add_gyuanx_name_system_tx_renew(miner, gen.hardfork(), lns::mapping_type::gyuanxnet_5years, name);
  gen.create_and_add_next_block({renew_tx});
  renew_tx = gen.create_and_add_gyuanx_name_system_tx_renew(miner, gen.hardfork(), lns::mapping_type::gyuanxnet_10years, name);
  gen.create_and_add_next_block({renew_tx});
  renew_tx = gen.create_and_add_gyuanx_name_system_tx_renew(miner, gen.hardfork(), lns::mapping_type::gyuanxnet_2years, name);
  gen.create_and_add_next_block({renew_tx});
  renew_tx = gen.create_and_add_gyuanx_name_system_tx_renew(miner, gen.hardfork(), lns::mapping_type::gyuanxnet, name);
  gen.create_and_add_next_block({renew_tx});
  crypto::hash txid       = cryptonote::get_transaction_hash(renew_tx);
  uint64_t renewal_height = gen.height();

  gyuanx_register_callback(events, "check_renewed", [=](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_renewed");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

    lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
    CHECK_EQ(owner.loaded, true);
    CHECK_EQ(owner.id, 1);
    CHECK_TEST_CONDITION_MSG(miner_key.owner == owner.address,
                             miner_key.owner.to_string(cryptonote::FAKECHAIN)
                                 << " == " << owner.address.to_string(cryptonote::FAKECHAIN));

    std::string name_hash = lns::name_to_base64_hash(name);
    lns::mapping_record record = lns_db.get_mapping(lns::mapping_type::gyuanxnet, name_hash);
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::gyuanxnet, name, miner_key.gyuanxnet_value, renewal_height,
          // Original registration:
          height_of_lns_entry + gyuanxnet_expiry(lns::mapping_type::gyuanxnet)
          // The renewals:
          + gyuanxnet_expiry(lns::mapping_type::gyuanxnet_5years)
          + gyuanxnet_expiry(lns::mapping_type::gyuanxnet_10years)
          + gyuanxnet_expiry(lns::mapping_type::gyuanxnet_2years)
          + gyuanxnet_expiry(lns::mapping_type::gyuanxnet),
          txid, miner_key.owner, {} /*backup_owner*/));
    return true;
  });

  return true;
}

bool gyuanx_name_system_name_value_max_lengths::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  auto make_lns_tx_with_custom_extra = [&](gyuanx_chain_generator &gen,
                                           std::vector<test_event_entry> &events,
                                           cryptonote::account_base const &src,
                                           cryptonote::tx_extra_gyuanx_name_system const &data) -> void {

    uint64_t new_height    = cryptonote::get_block_height(gen.top().block) + 1;
    uint8_t new_hf_version = gen.get_hf_version_at(new_height);
    uint64_t burn_requirement = lns::burn_needed(new_hf_version, static_cast<lns::mapping_type>(data.type));
    std::vector<uint8_t> extra;
    cryptonote::add_gyuanx_name_system_to_tx_extra(extra, data);
    cryptonote::add_burned_amount_to_tx_extra(extra, burn_requirement);

    cryptonote::transaction tx = {};
    gyuanx_tx_builder(events, tx, gen.top().block, src /*from*/, src.get_keys().m_account_address, 0, new_hf_version)
        .with_tx_type(cryptonote::txtype::gyuanx_name_system)
        .with_extra(extra)
        .with_fee(burn_requirement + TESTS_DEFAULT_FEE)
        .build();

    gen.add_tx(tx, true /*can_be_added_to_blockchain*/, "", false /*kept_by_block*/);
  };

  lns_keys_t miner_key = make_lns_keys(miner);
  cryptonote::tx_extra_gyuanx_name_system data = {};
  data.fields |= lns::extra_field::buy_no_backup;
  data.owner = miner_key.owner;

  // Wallet
  if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::wallet))
  {
    std::string name(lns::WALLET_NAME_MAX, 'a');
    data.type            = lns::mapping_type::wallet;
    data.name_hash       = lns::name_to_hash(name);
    data.encrypted_value = miner_key.wallet_value.make_encrypted(name).to_string();
    make_lns_tx_with_custom_extra(gen, events, miner, data);
  }

  // Gyuanxnet
  if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::gyuanxnet))
  {
    std::string name(lns::GYUANXNET_DOMAIN_NAME_MAX, 'a');
    name.replace(name.size() - 6, 5, ".gyuanx");

    data.type            = lns::mapping_type::gyuanxnet;
    data.name_hash       = lns::name_to_hash(name);
    data.encrypted_value = miner_key.gyuanxnet_value.make_encrypted(name).to_string();
    make_lns_tx_with_custom_extra(gen, events, miner, data);
  }

  // Session
  {
    std::string name(lns::SESSION_DISPLAY_NAME_MAX, 'a');
    data.type            = lns::mapping_type::session;
    data.name_hash       = lns::name_to_hash(name);
    data.encrypted_value = miner_key.session_value.make_encrypted(name).to_string();
    make_lns_tx_with_custom_extra(gen, events, miner, data);
  }

  return true;
}

bool gyuanx_name_system_update_mapping_after_expiry_fails::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);
  cryptonote::account_base miner = gen.first_miner_;

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  lns_keys_t miner_key = make_lns_keys(miner);
  if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::gyuanxnet))
  {
    std::string const name     = "mydomain.gyuanx";
    cryptonote::transaction tx = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::gyuanxnet, name, miner_key.gyuanxnet_value);
    crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);
    gen.create_and_add_next_block({tx});

    uint64_t height_of_lns_entry   = gen.height();
    uint64_t expected_expiry_block = height_of_lns_entry + gyuanxnet_expiry(lns::mapping_type::gyuanxnet);

    while (gen.height() <= expected_expiry_block)
      gen.create_and_add_next_block();

    {
      lns_keys_t bob_key = make_lns_keys(gen.add_account());
      cryptonote::transaction tx1 = gen.create_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::gyuanxnet, name, &bob_key.gyuanxnet_value);
      gen.add_tx(tx1, false /*can_be_added_to_blockchain*/, "Can not update a LNS record that is already expired");
    }

    gyuanx_register_callback(events, "check_still_expired", [=, blockchain_height=gen.chain_height()](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_still_expired");
      lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

      lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
      CHECK_EQ(owner.loaded, true);
      CHECK_EQ(owner.id, 1);
      CHECK_TEST_CONDITION_MSG(miner_key.owner == owner.address,
                               miner_key.owner.to_string(cryptonote::FAKECHAIN)
                                   << " == " << owner.address.to_string(cryptonote::FAKECHAIN));

      std::string name_hash        = lns::name_to_base64_hash(name);
      lns::mapping_record record = lns_db.get_mapping(lns::mapping_type::gyuanxnet, name_hash);
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::gyuanxnet, name, miner_key.gyuanxnet_value, height_of_lns_entry, height_of_lns_entry + gyuanxnet_expiry(lns::mapping_type::gyuanxnet), tx_hash, miner_key.owner, {} /*backup_owner*/));
      CHECK_EQ(record.active(blockchain_height), false);
      CHECK_EQ(record.owner_id, owner.id);
      return true;
    });
  }
  return true;
}

uint8_t gyuanx_name_system_update_mapping::hf() { return cryptonote::network_version_count - 1; }
uint8_t gyuanx_name_system_update_mapping_argon2::hf() { return cryptonote::network_version_15_lns; }
bool gyuanx_name_system_update_mapping::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table(hf());
  gyuanx_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base miner     = gen.first_miner_;
  cryptonote::account_base const bob = gen.add_account();
  lns_keys_t miner_key               = make_lns_keys(miner);
  lns_keys_t bob_key                 = make_lns_keys(bob);

  crypto::hash session_tx_hash1;
  std::string session_name1 = "myname";
  {
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::session, session_name1, miner_key.session_value);
    session_tx_hash1 = cryptonote::get_transaction_hash(tx1);
    gen.create_and_add_next_block({tx1});
  }
  uint64_t register_height = gen.height();

  gyuanx_register_callback(events, "check_registered", [=](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_registered");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

    std::string name_hash = lns::name_to_base64_hash(session_name1);
    std::vector<lns::mapping_record> records = lns_db.get_mappings({lns::mapping_type::session}, name_hash);

    CHECK_EQ(records.size(), 1);
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[0], lns::mapping_type::session, session_name1, miner_key.session_value, register_height, std::nullopt, session_tx_hash1, miner_key.owner, {} /*backup_owner*/));
    return true;
  });

  // Test update mapping with same name fails
  if (hf() == cryptonote::network_version_15_lns) {
    cryptonote::transaction tx1 = gen.create_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, session_name1, &miner_key.session_value);
    gen.add_tx(tx1, false /*can_be_added_to_blockchain*/, "Can not add a LNS TX that re-updates the underlying value to same value");
  }

  crypto::hash session_tx_hash2;
  {
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, session_name1, &bob_key.session_value);
    session_tx_hash2 = cryptonote::get_transaction_hash(tx1);
    gen.create_and_add_next_block({tx1});
  }

  gyuanx_register_callback(events, "check_updated", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_updated");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

    std::string name_hash = lns::name_to_base64_hash(session_name1);
    std::vector<lns::mapping_record> records = lns_db.get_mappings({lns::mapping_type::session}, name_hash);

    CHECK_EQ(records.size(), 1);
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[0], lns::mapping_type::session, session_name1, bob_key.session_value, blockchain_height, std::nullopt, session_tx_hash2, miner_key.owner, {} /*backup_owner*/));
    return true;
  });

  return true;
}

bool gyuanx_name_system_update_mapping_multiple_owners::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(10); /// generate some outputs and unlock them
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base miner = gen.first_miner_;
  lns_keys_t miner_key           = make_lns_keys(miner);

  // Test 2 ed keys as owner
  {
    lns::generic_owner owner1;
    lns::generic_owner owner2;
    crypto::ed25519_secret_key owner1_key;
    crypto::ed25519_secret_key owner2_key;

    crypto_sign_ed25519_keypair(owner1.ed25519.data, owner1_key.data);
    crypto_sign_ed25519_keypair(owner2.ed25519.data, owner2_key.data);
    owner1.type = lns::generic_owner_sig_type::ed25519;
    owner2.type = lns::generic_owner_sig_type::ed25519;

    std::string name      = "hello_world";
    std::string name_hash = lns::name_to_base64_hash(name);
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::session, name, miner_key.session_value, &owner1, &owner2);
    gen.create_and_add_next_block({tx1});
    uint64_t height = gen.height();
    crypto::hash txid      = cryptonote::get_transaction_hash(tx1);

    gyuanx_register_callback(events, "check_update0", [=](cryptonote::core &c, size_t ev_index)
    {
      const char* perr_context = "check_update0";
      lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
      lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, miner_key.session_value, height, std::nullopt, txid, owner1, owner2 /*backup_owner*/));
      return true;
    });

    // Update with owner1
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());
      lns::mapping_value encrypted_value = temp_keys.session_value.make_encrypted(name);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_ed25519_signature(hash, owner1_key);

      cryptonote::transaction tx2 = gen.create_and_add_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, name, &encrypted_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      txid      = cryptonote::get_transaction_hash(tx2);

      gyuanx_register_callback(events, "check_update1", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update1";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, blockchain_height, std::nullopt, txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }

    // Update with owner2
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());
      lns::mapping_value encrypted_value = temp_keys.session_value.make_encrypted(name);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_ed25519_signature(hash, owner2_key);

      cryptonote::transaction tx2 = gen.create_and_add_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, name, &encrypted_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      txid      = cryptonote::get_transaction_hash(tx2);

      gyuanx_register_callback(events, "check_update2", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update2";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, blockchain_height, std::nullopt, txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }
  }

  // Test 2 monero keys as owner
  {
    cryptonote::account_base account1 = gen.add_account();
    cryptonote::account_base account2 = gen.add_account();
    lns::generic_owner owner1         = lns::make_monero_owner(account1.get_keys().m_account_address, false /*subaddress*/);
    lns::generic_owner owner2         = lns::make_monero_owner(account2.get_keys().m_account_address, false /*subaddress*/);

    std::string name            = "hello_sailor";
    std::string name_hash = lns::name_to_base64_hash(name);
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::session, name, miner_key.session_value, &owner1, &owner2);
    gen.create_and_add_next_block({tx1});
    uint64_t height        = gen.height();
    crypto::hash txid      = cryptonote::get_transaction_hash(tx1);

    // Update with owner1
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());
      lns::mapping_value encrypted_value = temp_keys.session_value.make_encrypted(name);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_monero_signature(hash, owner1.wallet.address.m_spend_public_key, account1.get_keys().m_spend_secret_key);

      cryptonote::transaction tx2 = gen.create_and_add_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, name, &encrypted_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      txid      = cryptonote::get_transaction_hash(tx2);

      gyuanx_register_callback(events, "check_update3", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update3";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, blockchain_height, std::nullopt, txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }

    // Update with owner2
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());
      lns::mapping_value encrypted_value = temp_keys.session_value.make_encrypted(name);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_monero_signature(hash, owner2.wallet.address.m_spend_public_key, account2.get_keys().m_spend_secret_key);

      cryptonote::transaction tx2 = gen.create_and_add_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, name, &encrypted_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      txid      = cryptonote::get_transaction_hash(tx2);

      gyuanx_register_callback(events, "check_update3", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update3";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, blockchain_height, std::nullopt, txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }
  }

  // Test 1 ed/1 monero as owner
  {
    cryptonote::account_base account2 = gen.add_account();

    lns::generic_owner owner1;
    lns::generic_owner owner2 = lns::make_monero_owner(account2.get_keys().m_account_address, false /*subaddress*/);
    crypto::ed25519_secret_key owner1_key;

    crypto_sign_ed25519_keypair(owner1.ed25519.data, owner1_key.data);
    owner1.type = lns::generic_owner_sig_type::ed25519;

    std::string name = "hello_driver";
    std::string name_hash = lns::name_to_base64_hash(name);
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::session, name, miner_key.session_value, &owner1, &owner2);
    gen.create_and_add_next_block({tx1});
    uint64_t height        = gen.height();
    crypto::hash txid      = cryptonote::get_transaction_hash(tx1);

    // Update with owner1
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());
      lns::mapping_value encrypted_value = temp_keys.session_value.make_encrypted(name);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_ed25519_signature(hash, owner1_key);

      cryptonote::transaction tx2 = gen.create_and_add_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, name, &encrypted_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      txid      = cryptonote::get_transaction_hash(tx2);

      gyuanx_register_callback(events, "check_update4", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update4";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, blockchain_height, std::nullopt, txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }

    // Update with owner2
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());
      lns::mapping_value encrypted_value = temp_keys.session_value.make_encrypted(name);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_monero_signature(hash, owner2.wallet.address.m_spend_public_key, account2.get_keys().m_spend_secret_key);

      cryptonote::transaction tx2 = gen.create_and_add_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, name, &encrypted_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      txid      = cryptonote::get_transaction_hash(tx2);

      gyuanx_register_callback(events, "check_update5", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update5";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, blockchain_height, std::nullopt, txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }
  }

  // Test 1 monero/1 ed as owner
  {
    cryptonote::account_base account1 = gen.add_account();
    lns::generic_owner owner1         = lns::make_monero_owner(account1.get_keys().m_account_address, false /*subaddress*/);
    lns::generic_owner owner2;

    crypto::ed25519_secret_key owner2_key;
    crypto_sign_ed25519_keypair(owner2.ed25519.data, owner2_key.data);
    owner2.type = lns::generic_owner_sig_type::ed25519;

    std::string name = "hello_passenger";
    std::string name_hash = lns::name_to_base64_hash(name);
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::session, name, miner_key.session_value, &owner1, &owner2);
    gen.create_and_add_next_block({tx1});
    uint64_t height        = gen.height();
    crypto::hash txid      = cryptonote::get_transaction_hash(tx1);

    // Update with owner1
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());

      lns::mapping_value encrypted_value = temp_keys.session_value.make_encrypted(name);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_monero_signature(hash, owner1.wallet.address.m_spend_public_key, account1.get_keys().m_spend_secret_key);

      cryptonote::transaction tx2 = gen.create_and_add_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, name, &encrypted_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      txid      = cryptonote::get_transaction_hash(tx2);

      gyuanx_register_callback(events, "check_update6", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update6";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, blockchain_height, std::nullopt, txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }

    // Update with owner2
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());

      lns::mapping_value encrypted_value = temp_keys.session_value.make_encrypted(name);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_ed25519_signature(hash, owner2_key);

      cryptonote::transaction tx2 = gen.create_and_add_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, name, &encrypted_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      txid      = cryptonote::get_transaction_hash(tx2);

      gyuanx_register_callback(events, "check_update7", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update7";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, blockchain_height, std::nullopt, txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }
  }
  return true;
}

bool gyuanx_name_system_update_mapping_non_existent_name_fails::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base miner = gen.first_miner_;
  lns_keys_t miner_key           = make_lns_keys(miner);
  std::string name               = "hello-world";
  cryptonote::transaction tx1 = gen.create_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, name, &miner_key.session_value, nullptr /*owner*/, nullptr /*backup_owner*/, nullptr /*signature*/, false /*use_asserts*/);
  gen.add_tx(tx1, false /*can_be_added_to_blockchain*/, "Can not add a updating LNS TX referencing a non-existent LNS entry");
  return true;
}

bool gyuanx_name_system_update_mapping_invalid_signature::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base miner = gen.first_miner_;
  lns_keys_t miner_key           = make_lns_keys(miner);

  std::string const name = "hello-world";
  cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::session, name, miner_key.session_value);
  gen.create_and_add_next_block({tx1});

  lns_keys_t bob_key = make_lns_keys(gen.add_account());
  lns::mapping_value encrypted_value = bob_key.session_value.make_encrypted(name);
  lns::generic_signature invalid_signature = {};
  cryptonote::transaction tx2 = gen.create_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, name, &encrypted_value, nullptr /*owner*/, nullptr /*backup_owner*/, &invalid_signature, false /*use_asserts*/);
  gen.add_tx(tx2, false /*can_be_added_to_blockchain*/, "Can not add a updating LNS TX with an invalid signature");
  return true;
}

bool gyuanx_name_system_update_mapping_replay::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base miner = gen.first_miner_;
  lns_keys_t miner_key           = make_lns_keys(miner);
  lns_keys_t bob_key             = make_lns_keys(gen.add_account());
  lns_keys_t alice_key           = make_lns_keys(gen.add_account());

  std::string const name = "hello-world";
  // Make LNS Mapping
  {
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx(miner, gen.hardfork(), lns::mapping_type::session, name, miner_key.session_value);
    gen.create_and_add_next_block({tx1});
  }

  // (1) Update LNS Mapping
  cryptonote::tx_extra_gyuanx_name_system lns_entry = {};
  {
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, name, &bob_key.session_value);
    gen.create_and_add_next_block({tx1});
    [[maybe_unused]] bool found_tx_extra = cryptonote::get_field_from_tx_extra(tx1.extra, lns_entry);
    assert(found_tx_extra);
  }

  // Replay the (1)st update mapping, should fail because the update is to the same session value
  {
    cryptonote::transaction tx1 = gen.create_gyuanx_name_system_tx_update_w_extra(miner, gen.hardfork(), lns_entry);
    gen.add_tx(tx1, false /*can_be_added_to_blockchain*/, "Can not replay an older update mapping to the same session value");
  }

  // (2) Update Again
  crypto::hash new_hash = {};
  {
    cryptonote::transaction tx1 = gen.create_and_add_gyuanx_name_system_tx_update(miner, gen.hardfork(), lns::mapping_type::session, name, &alice_key.session_value);
    gen.create_and_add_next_block({tx1});
    new_hash = cryptonote::get_transaction_hash(tx1);
  }

  // Replay the (1)st update mapping, should fail now even though it's not to the same session value, but that the signature no longer matches so you can't replay.
  lns_entry.prev_txid = new_hash;
  {
    cryptonote::transaction tx1 = gen.create_gyuanx_name_system_tx_update_w_extra(miner, gen.hardfork(), lns_entry);
    gen.add_tx(tx1, false /*can_be_added_to_blockchain*/, "Can not replay an older update mapping, should fail signature verification");
  }

  return true;
}

bool gyuanx_name_system_wrong_burn::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);
  cryptonote::account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().first);

  // NOTE: Fund Miner's wallet
  {
    gen.add_mined_money_unlock_blocks();
  }

  lns_keys_t lns_keys             = make_lns_keys(miner);
  lns::mapping_type const types[] = {lns::mapping_type::session, lns::mapping_type::wallet, lns::mapping_type::gyuanxnet};
  for (int i = 0; i < 2; i++)
  {
    bool under_burn = (i == 0);
    for (auto const type : types)
    {
      if (lns::mapping_type_allowed(gen.hardfork(), type))
      {
        lns::mapping_value value = {};
        std::string name;

        if (type == lns::mapping_type::session)
        {
          value = lns_keys.session_value;
          name  = "my-friendly-session-name";
        }
        else if (type == lns::mapping_type::wallet)
        {
          value = lns_keys.wallet_value;
          name = "my-friendly-wallet-name";
        }
        else if (type == lns::mapping_type::gyuanxnet)
        {
          value = lns_keys.gyuanxnet_value;
          name  = "myfriendlygyuanxnetname.gyuanx";
        }
        else
            assert("Unhandled type enum" == nullptr);

        uint64_t new_height      = cryptonote::get_block_height(gen.top().block) + 1;
        uint8_t new_hf_version   = gen.get_hf_version_at(new_height);
        uint64_t burn            = lns::burn_needed(new_hf_version, type);
        if (under_burn) burn -= 1;
        else            burn += 1;

        cryptonote::transaction tx = gen.create_gyuanx_name_system_tx(miner, gen.hardfork(), type, name, value, nullptr /*owner*/, nullptr /*backup_owner*/, burn);
        gen.add_tx(tx, false /*can_be_added_to_blockchain*/, "Wrong burn for a LNS tx", false /*kept_by_block*/);
      }
    }
  }
  return true;
}

bool gyuanx_name_system_wrong_version::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  std::string name = "lns_name";
  lns_keys_t miner_key                       = make_lns_keys(miner);
  cryptonote::tx_extra_gyuanx_name_system data = {};
  data.version                               = 0xFF;
  data.owner                                 = miner_key.owner;
  data.type                                  = lns::mapping_type::session;
  data.name_hash                             = lns::name_to_hash(name);
  data.encrypted_value                       = miner_key.session_value.make_encrypted(name).to_string();

  uint64_t new_height       = cryptonote::get_block_height(gen.top().block) + 1;
  uint8_t new_hf_version    = gen.get_hf_version_at(new_height);
  uint64_t burn_requirement = lns::burn_needed(new_hf_version, lns::mapping_type::session);

  std::vector<uint8_t> extra;
  cryptonote::add_gyuanx_name_system_to_tx_extra(extra, data);
  cryptonote::add_burned_amount_to_tx_extra(extra, burn_requirement);

  cryptonote::transaction tx = {};
  gyuanx_tx_builder(events, tx, gen.top().block, miner /*from*/, miner.get_keys().m_account_address, 0, new_hf_version)
      .with_tx_type(cryptonote::txtype::gyuanx_name_system)
      .with_extra(extra)
      .with_fee(burn_requirement + TESTS_DEFAULT_FEE)
      .build();

  gen.add_tx(tx, false /*can_be_added_to_blockchain*/, "Incorrect LNS record version specified", false /*kept_by_block*/);
  return true;
}

// NOTE: Generate forked block, check that alternative quorums are generated and accessible
bool gyuanx_gnodes_alt_quorums::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();
  add_gnodes(gen, gnodes::STATE_CHANGE_QUORUM_SIZE + 3);

  gyuanx_chain_generator fork = gen;
  gen.create_and_add_next_block();
  fork.create_and_add_next_block();
  uint64_t height_with_fork = gen.height();

  gnodes::quorum_manager fork_quorums = fork.top_quorum();
  gyuanx_register_callback(events, "check_alt_quorums_exist", [fork_quorums, height_with_fork](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_alt_quorums_exist");

    std::vector<std::shared_ptr<const gnodes::quorum>> alt_quorums;
    c.get_quorum(gnodes::quorum_type::obligations, height_with_fork, false /*include_old*/, &alt_quorums);
    CHECK_TEST_CONDITION_MSG(alt_quorums.size() == 1, "alt_quorums.size(): " << alt_quorums.size());

    gnodes::quorum const &fork_obligation_quorum = *fork_quorums.obligations;
    gnodes::quorum const &real_obligation_quorum = *(alt_quorums[0]);
    CHECK_TEST_CONDITION(fork_obligation_quorum.validators.size() == real_obligation_quorum.validators.size());
    CHECK_TEST_CONDITION(fork_obligation_quorum.workers.size() == real_obligation_quorum.workers.size());

    for (size_t i = 0; i < fork_obligation_quorum.validators.size(); i++)
    {
      crypto::public_key const &fork_key = fork_obligation_quorum.validators[i];
      crypto::public_key const &real_key = real_obligation_quorum.validators[i];
      CHECK_EQ(fork_key, real_key);
    }

    for (size_t i = 0; i < fork_obligation_quorum.workers.size(); i++)
    {
      crypto::public_key const &fork_key = fork_obligation_quorum.workers[i];
      crypto::public_key const &real_key = real_obligation_quorum.workers[i];
      CHECK_EQ(fork_key, real_key);
    }

    return true;
  });

  return true;
}

bool gyuanx_gnodes_checkpoint_quorum_size::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();
  add_gnodes(gen, gnodes::CHECKPOINT_QUORUM_SIZE - 1);

  for (int i = 0; i < 16; i++)
  {
    gen.create_and_add_next_block();
    std::shared_ptr<const gnodes::quorum> quorum = gen.get_quorum(gnodes::quorum_type::checkpointing, gen.height());
    if (quorum) break;
  }

  gyuanx_register_callback(events, "check_checkpoint_quorum_should_be_empty", [check_height_1 = gen.height()](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_checkpoint_quorum_should_be_empty");
    std::shared_ptr<const gnodes::quorum> quorum = c.get_quorum(gnodes::quorum_type::checkpointing, check_height_1);
    CHECK_TEST_CONDITION(quorum != nullptr);
    CHECK_TEST_CONDITION(quorum->validators.size() == 0);
    return true;
  });

  cryptonote::transaction new_registration_tx = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block({new_registration_tx});
  gen.add_blocks_until_next_checkpointable_height();
  gyuanx_register_callback(events, "check_checkpoint_quorum_should_be_populated", [check_height_2 = gen.height()](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_checkpoint_quorum_should_be_populated");
    std::shared_ptr<const gnodes::quorum> quorum = c.get_quorum(gnodes::quorum_type::checkpointing, check_height_2);
    CHECK_TEST_CONDITION(quorum != nullptr);
    CHECK_TEST_CONDITION(quorum->validators.size() > 0);
    return true;
  });

  return true;
}

bool gyuanx_gnodes_gen_nodes::generate(std::vector<test_event_entry> &events)
{
  const std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table(cryptonote::network_version_9_gnodes);
  gyuanx_chain_generator gen(events, hard_forks);
  const auto miner                      = gen.first_miner();
  const auto alice                      = gen.add_account();
  size_t alice_account_base_event_index = gen.event_index();

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(10);
  gen.add_mined_money_unlock_blocks();

  const auto tx0 = gen.create_and_add_tx(miner, alice.get_keys().m_account_address, MK_COINS(101));
  gen.create_and_add_next_block({tx0});
  gen.add_mined_money_unlock_blocks();

  const auto reg_tx = gen.create_and_add_registration_tx(alice);
  gen.create_and_add_next_block({reg_tx});

  gyuanx_register_callback(events, "check_registered", [&events, alice](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("gen_gnodes::check_registered");
    std::vector<cryptonote::block> blocks;
    size_t count = 15 + (2 * CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
    bool r       = c.get_blocks((uint64_t)0, count, blocks);
    CHECK_TEST_CONDITION(r);
    std::vector<cryptonote::block> chain;
    map_hash2tx_t mtx;
    r = find_block_chain(events, chain, mtx, cryptonote::get_block_hash(blocks.back()));
    CHECK_TEST_CONDITION(r);

    // Expect the change to have unlock time of 0, and we get that back immediately ~0.8 gyuanx
    // 101 (balance) - 100 (stake) - 0.2 (test fee) = 0.8 gyuanx
    const uint64_t unlocked_balance    = get_unlocked_balance(alice, blocks, mtx);
    const uint64_t staking_requirement = MK_COINS(100);

    CHECK_EQ(MK_COINS(101) - TESTS_DEFAULT_FEE - staking_requirement, unlocked_balance);

    /// check that alice is registered
    const auto info_v = c.get_gnode_list_state({});
    CHECK_EQ(info_v.empty(), false);
    return true;
  });

  for (auto i = 0u; i < gnodes::staking_num_lock_blocks(cryptonote::FAKECHAIN); ++i)
    gen.create_and_add_next_block();

  gyuanx_register_callback(events, "check_expired", [&events, alice](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_expired");
    const auto stake_lock_time = gnodes::staking_num_lock_blocks(cryptonote::FAKECHAIN);

    std::vector<cryptonote::block> blocks;
    size_t count = 15 + (2 * CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW) + stake_lock_time;
    bool r = c.get_blocks((uint64_t)0, count, blocks);
    CHECK_TEST_CONDITION(r);
    std::vector<cryptonote::block> chain;
    map_hash2tx_t mtx;
    r = find_block_chain(events, chain, mtx, cryptonote::get_block_hash(blocks.back()));
    CHECK_TEST_CONDITION(r);

    /// check that alice's registration expired
    const auto info_v = c.get_gnode_list_state({});
    CHECK_EQ(info_v.empty(), true);

    /// check that alice received some service node rewards (TODO: check the balance precisely)
    CHECK_TEST_CONDITION(get_balance(alice, blocks, mtx) > MK_COINS(101) - TESTS_DEFAULT_FEE);
    return true;
  });
  return true;
}

using sn_info_t = gnodes::gnode_pubkey_info;
static bool contains(const std::vector<sn_info_t>& infos, const crypto::public_key& key)
{
  const auto it =
    std::find_if(infos.begin(), infos.end(), [&key](const sn_info_t& info) { return info.pubkey == key; });
  return it != infos.end();
}

bool gyuanx_gnodes_test_rollback::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table(cryptonote::network_version_9_gnodes);
  gyuanx_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(20); /// generate some outputs and unlock them
  gen.add_mined_money_unlock_blocks();
  add_gnodes(gen, 11);

  gen.add_n_blocks(5);   /// create a few blocks with active service nodes
  auto fork = gen;       /// chain split here

  // deregister some node (A) on main
  const auto pk           = gen.top_quorum().obligations->workers[0];
  const auto dereg_tx     = gen.create_and_add_state_change_tx(gnodes::new_state::deregister, pk);
  size_t deregister_index = gen.event_index();
  gen.create_and_add_next_block({dereg_tx});

  /// create a new service node (B) in the next block
  {
    const auto tx = gen.create_and_add_registration_tx(gen.first_miner());
    gen.create_and_add_next_block({tx});
  }

  fork.add_n_blocks(3); /// create blocks on the alt chain and trigger chain switch
  fork.add_n_blocks(15); // create a few more blocks to test winner selection
  gyuanx_register_callback(events, "test_registrations", [&events, deregister_index](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_registrations");
    const auto sn_list = c.get_gnode_list_state({});
    /// Test that node A is still registered
    {
      /// obtain public key of node A
      const auto event_a = events.at(deregister_index);
      CHECK_TEST_CONDITION(std::holds_alternative<gyuanx_blockchain_addable<gyuanx_transaction>>(event_a));
      const auto dereg_tx = var::get<gyuanx_blockchain_addable<gyuanx_transaction>>(event_a);
      CHECK_TEST_CONDITION(dereg_tx.data.tx.type == cryptonote::txtype::state_change);

      cryptonote::tx_extra_gnode_state_change deregistration;
      cryptonote::get_gnode_state_change_from_tx_extra(
          dereg_tx.data.tx.extra, deregistration, c.get_blockchain_storage().get_current_hard_fork_version());

      const auto uptime_quorum = c.get_quorum(gnodes::quorum_type::obligations, deregistration.block_height);
      CHECK_TEST_CONDITION(uptime_quorum);
      const auto pk_a = uptime_quorum->workers.at(deregistration.gnode_index);

      /// Check present
      const bool found_a = contains(sn_list, pk_a);
      CHECK_AND_ASSERT_MES(found_a, false, "Node deregistered in alt chain is not found in the main chain after reorg.");
    }

    /// Test that node B is not registered
    {
      /// obtain public key of node B
      constexpr size_t reg_evnt_idx = 73;
      const auto event_b = events.at(reg_evnt_idx);
      CHECK_TEST_CONDITION(std::holds_alternative<gyuanx_blockchain_addable<gyuanx_transaction>>(event_b));
      const auto reg_tx = var::get<gyuanx_blockchain_addable<gyuanx_transaction>>(event_b);

      crypto::public_key pk_b;
      if (!cryptonote::get_gnode_pubkey_from_tx_extra(reg_tx.data.tx.extra, pk_b)) {
        MERROR("Could not get service node key from tx extra");
        return false;
      }

      /// Check not present
      const bool found_b = contains(sn_list, pk_b);
      CHECK_AND_ASSERT_MES(!found_b, false, "Node registered in alt chain is present in the main chain after reorg.");
    }
    return true;
  });

  return true;
}

bool gyuanx_gnodes_test_swarms_basic::generate(std::vector<test_event_entry>& events)
{
  const std::vector<std::pair<uint8_t, uint64_t>> hard_forks = {
      std::make_pair(7, 0), std::make_pair(8, 1), std::make_pair(9, 2), std::make_pair(10, 150)};

  gyuanx_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.rbegin()[1].first);

  /// Create some service nodes before hf version 10
  constexpr size_t INIT_SN_COUNT  = 13;
  constexpr size_t TOTAL_SN_COUNT = 25;
  gen.add_n_blocks(90);
  gen.add_mined_money_unlock_blocks();

  /// register some service nodes
  add_gnodes(gen, INIT_SN_COUNT);

  /// create a few blocks with active service nodes
  gen.add_n_blocks(5);
  assert(gen.hf_version_ == cryptonote::network_version_9_gnodes);

  gen.add_blocks_until_version(cryptonote::network_version_10_bulletproofs);
  gyuanx_register_callback(events, "test_initial_swarms", [](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_swarms_basic::test_initial_swarms");
    const auto sn_list = c.get_gnode_list_state({}); /// Check that there is one active swarm and the swarm queue is not empty
    std::map<gnodes::swarm_id_t, std::vector<crypto::public_key>> swarms;
    for (const auto& entry : sn_list)
    {
      const auto id = entry.info->swarm_id;
      swarms[id].push_back(entry.pubkey);
    }

    CHECK_EQ(swarms.size(), 1);
    CHECK_EQ(swarms.begin()->second.size(), 13);
    return true;
  });

  /// rewind some blocks and register 1 more service node
  {
    const auto tx = gen.create_and_add_registration_tx(gen.first_miner());
    gen.create_and_add_next_block({tx});
  }

  gyuanx_register_callback(events, "test_with_one_more_sn", [](cryptonote::core &c, size_t ev_index) /// test that another swarm has been created
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_with_one_more_sn");
    const auto sn_list = c.get_gnode_list_state({});
    std::map<gnodes::swarm_id_t, std::vector<crypto::public_key>> swarms;
    for (const auto& entry : sn_list)
    {
      const auto id = entry.info->swarm_id;
      swarms[id].push_back(entry.pubkey);
    }
    CHECK_EQ(swarms.size(), 2);
    return true;
  });

  for (auto i = INIT_SN_COUNT + 1; i < TOTAL_SN_COUNT; ++i)
  {
    const auto tx = gen.create_and_add_registration_tx(gen.first_miner());
    gen.create_and_add_next_block({tx});
  }

  gyuanx_register_callback(events, "test_with_more_sn", [](cryptonote::core &c, size_t ev_index) /// test that another swarm has been created
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_with_more_sn");
    const auto sn_list = c.get_gnode_list_state({});
    std::map<gnodes::swarm_id_t, std::vector<crypto::public_key>> swarms;
    for (const auto& entry : sn_list)
    {
      const auto id = entry.info->swarm_id;
      swarms[id].push_back(entry.pubkey);
    }
    CHECK_EQ(swarms.size(), 3);
    return true;
  });

  std::vector<cryptonote::transaction> dereg_txs; /// deregister enough snode to bring all 3 swarm to the min size
  const size_t excess = TOTAL_SN_COUNT - 3 * gnodes::EXCESS_BASE;
  gnodes::quorum_manager top_quorum = gen.top_quorum();
  for (size_t i = 0; i < excess; ++i)
  {
    const auto pk = top_quorum.obligations->workers[i];
    const auto tx = gen.create_and_add_state_change_tx(gnodes::new_state::deregister, pk, cryptonote::get_block_height(gen.top().block));
    dereg_txs.push_back(tx);
  }

  gen.create_and_add_next_block(dereg_txs);
  gyuanx_register_callback(events, "test_after_first_deregisters", [](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_after_first_deregisters");
    const auto sn_list = c.get_gnode_list_state({});
    std::map<gnodes::swarm_id_t, std::vector<crypto::public_key>> swarms;
    for (const auto& entry : sn_list)
    {
      const auto id = entry.info->swarm_id;
      swarms[id].push_back(entry.pubkey);
    }
    CHECK_EQ(swarms.size(), 3);
    return true;
  });

  /// deregister 1 snode, which should trigger a decommission
  dereg_txs.clear();
  {
    const auto pk = gen.top_quorum().obligations->workers[0];
    const auto tx = gen.create_and_add_state_change_tx(gnodes::new_state::deregister, pk);
    dereg_txs.push_back(tx);
  }
  gen.create_and_add_next_block(dereg_txs);

  gyuanx_register_callback(events, "test_after_final_deregisters", [](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_after_first_deregisters");
    const auto sn_list = c.get_gnode_list_state({});
    std::map<gnodes::swarm_id_t, std::vector<crypto::public_key>> swarms;
    for (const auto &entry : sn_list)
    {
      const auto id = entry.info->swarm_id;
      swarms[id].push_back(entry.pubkey);
    }

    CHECK_EQ(swarms.size(), 2);
    return true;
  });

  gen.add_n_blocks(5); /// test (implicitly) that deregistered nodes do not receive rewards
  return true;
}

bool gyuanx_gnodes_insufficient_contribution::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  uint64_t operator_portions                = STAKING_PORTIONS / 2;
  uint64_t remaining_portions               = STAKING_PORTIONS - operator_portions;
  cryptonote::keypair sn_keys               = cryptonote::keypair::generate(hw::get_device("default"));
  cryptonote::transaction register_tx       = gen.create_registration_tx(gen.first_miner_, sn_keys, operator_portions);
  gen.add_tx(register_tx);
  gen.create_and_add_next_block({register_tx});

  cryptonote::transaction stake = gen.create_and_add_staking_tx(sn_keys.pub, gen.first_miner_, MK_COINS(1));
  gen.create_and_add_next_block({stake});

  gyuanx_register_callback(events, "test_insufficient_stake_does_not_get_accepted", [sn_keys](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_insufficient_stake_does_not_get_accepted");
    const auto sn_list = c.get_gnode_list_state({sn_keys.pub});
    CHECK_TEST_CONDITION(sn_list.size() == 1);

    gnodes::gnode_pubkey_info const &pubkey_info = sn_list[0];
    CHECK_EQ(pubkey_info.info->total_contributed, MK_COINS(50));
    return true;
  });

  return true;
}

static gyuanx_chain_generator setup_pulse_tests(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator result(events, hard_forks);

  result.add_blocks_until_version(hard_forks.back().first);
  result.add_mined_money_unlock_blocks();

  std::vector<cryptonote::transaction> registration_txs(gnodes::pulse_min_gnodes(cryptonote::FAKECHAIN));
  for (auto i = 0u; i < gnodes::pulse_min_gnodes(cryptonote::FAKECHAIN); ++i)
    registration_txs[i] = result.create_and_add_registration_tx(result.first_miner());

  // NOTE: Generate Valid Blocks
  result.create_and_add_next_block({registration_txs});
  result.create_and_add_next_block();
  return result;
}

bool gyuanx_pulse_invalid_validator_bitset::generate(std::vector<test_event_entry> &events)
{
  gyuanx_chain_generator gen = setup_pulse_tests(events);
  gen.add_event_msg("Invalid Block: Validator bitset wrong");
  gyuanx_blockchain_entry entry     = {};
  gyuanx_create_block_params params = gen.next_block_params();
  gen.block_begin(entry, params, {} /*tx_list*/);

  // NOTE: Overwrite valiadator bitset to be wrong
  entry.block.pulse.validator_bitset = ~gnodes::pulse_validator_bit_mask();

  gen.block_end(entry, params);
  gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Invalid Pulse Block, specifies the wrong validator bitset");

  return true;
}

bool gyuanx_pulse_invalid_signature::generate(std::vector<test_event_entry> &events)
{
  gyuanx_chain_generator gen = setup_pulse_tests(events);
  gen.add_event_msg("Invalid Block: Wrong signature given (null signature)");
  gyuanx_blockchain_entry entry     = {};
  gyuanx_create_block_params params = gen.next_block_params();
  gen.block_begin(entry, params, {} /*tx_list*/);

  // NOTE: Overwrite signature
  entry.block.signatures[0].signature = {};
  gen.block_end(entry, params);
  gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Invalid Pulse Block, specifies the wrong validator bitset");

  return true;
}

bool gyuanx_pulse_oob_voter_index::generate(std::vector<test_event_entry> &events)
{
  gyuanx_chain_generator gen = setup_pulse_tests(events);
  gen.add_event_msg("Invalid Block: Quorum index that indexes out of bounds");
  gyuanx_blockchain_entry entry     = {};
  gyuanx_create_block_params params = gen.next_block_params();
  gen.block_begin(entry, params, {} /*tx_list*/);

  // NOTE: Overwrite oob voter index
  entry.block.signatures.back().voter_index = gnodes::PULSE_QUORUM_NUM_VALIDATORS + 1;
  gen.block_end(entry, params);
  gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Invalid Pulse Block, specifies the wrong validator bitset");

  return true;
}

bool gyuanx_pulse_non_participating_validator::generate(std::vector<test_event_entry> &events)
{
  gyuanx_chain_generator gen = setup_pulse_tests(events);
  gen.add_event_msg("Invalid Block: Validator gave signature but is not locked in to participate this round.");
  gyuanx_blockchain_entry entry     = {};
  gyuanx_create_block_params params = gen.next_block_params();
  gen.block_begin(entry, params, {} /*tx_list*/);

  // NOTE: Manually generate signatures to break test
  {
    entry.block.pulse = {};
    entry.block.signatures.clear();

    {
      entry.block.pulse.round = 0;
      for (size_t i = 0; i < sizeof(entry.block.pulse.random_value.data); i++)
        entry.block.pulse.random_value.data[i] = static_cast<char>(tools::uniform_distribution_portable(tools::rng, 256));
    }

    gnodes::quorum quorum = {};
    {
      std::vector<gnodes::pubkey_and_sninfo> active_snode_list = params.prev.gnode_state.active_gnodes_infos();
      std::vector<crypto::hash> entropy = gnodes::get_pulse_entropy_for_next_block(gen.db_, params.prev.block, entry.block.pulse.round);
      quorum = generate_pulse_quorum(cryptonote::FAKECHAIN, params.block_leader.key, entry.block.major_version, active_snode_list, entropy, entry.block.pulse.round);
      assert(quorum.validators.size() == gnodes::PULSE_QUORUM_NUM_VALIDATORS);
      assert(quorum.workers.size() == 1);
    }

    // NOTE: First 7 validators are locked in. We received signatures from the
    // first 6 in the quorum, then the 8th validator in the quorum (who is not
    // meant to be participating).
    static_assert(gnodes::PULSE_QUORUM_NUM_VALIDATORS > gnodes::PULSE_BLOCK_REQUIRED_SIGNATURES);
    entry.block.pulse.validator_bitset = 0b0000'000'0111'1111;
    size_t const voter_indexes[]       = {0, 1, 2, 3, 4, 5, 7};

    crypto::hash block_hash = cryptonote::get_block_hash(entry.block);
    for (size_t index : voter_indexes)
    {
      gnodes::gnode_keys validator_keys = gen.get_cached_keys(quorum.validators[index]);
      assert(validator_keys.pub == quorum.validators[index]);

      gnodes::quorum_signature signature = {};
      signature.voter_index                     = index;
      crypto::generate_signature(block_hash, validator_keys.pub, validator_keys.key, signature.signature);
      entry.block.signatures.push_back(signature);
    }
  }

  gen.block_end(entry, params);
  gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Invalid Pulse Block, specifies the wrong validator bitset");

  return true;
}

bool gyuanx_pulse_generate_all_rounds::generate(std::vector<test_event_entry> &events)
{
  gyuanx_chain_generator gen = setup_pulse_tests(events);

  for (uint8_t round = 0; round < static_cast<uint8_t>(-1); round++)
  {
    gyuanx_blockchain_entry entry     = {};
    gyuanx_create_block_params params = gen.next_block_params();
    params.pulse_round              = round;
    gen.block_begin(entry, params, {} /*tx_list*/);
    gen.block_end(entry, params);
    gen.add_block(entry, true);
  }

  return true;
}

bool gyuanx_pulse_out_of_order_voters::generate(std::vector<test_event_entry> &events)
{
  gyuanx_chain_generator gen = setup_pulse_tests(events);
  gen.add_event_msg("Invalid Block: Quorum voters are out of order");
  gyuanx_blockchain_entry entry     = {};
  gyuanx_create_block_params params = gen.next_block_params();
  gen.block_begin(entry, params, {} /*tx_list*/);
  // NOTE: Swap voters so that the votes are not sorted in order
  auto tmp                       = entry.block.signatures.back();
  entry.block.signatures.back()  = entry.block.signatures.front();
  entry.block.signatures.front() = tmp;
  gen.block_end(entry, params);
  gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Invalid Pulse Block, specifies the signatures not in sorted order");

  return true;
}

bool gyuanx_pulse_reject_miner_block::generate(std::vector<test_event_entry> &events)
{
  gyuanx_chain_generator gen = setup_pulse_tests(events);
  gen.add_event_msg("Invalid Block: PoW Block but we have enough service nodes for Pulse");
  gyuanx_blockchain_entry entry     = {};
  gyuanx_create_block_params params = gen.next_block_params();
  params.type = gyuanx_create_block_type::miner;
  gen.block_begin(entry, params, {} /*tx_list*/);

  // NOTE: Create an ordinary miner block even when we have enough Service Nodes for Pulse.
  fill_nonce_with_gyuanx_generator(&gen, entry.block, TEST_DEFAULT_DIFFICULTY, cryptonote::get_block_height(entry.block));

  gen.block_end(entry, params);
  gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Invalid Pulse Block, block was mined with a miner but we have enough nodes for Pulse");
  return true;
}

bool gyuanx_pulse_generate_blocks::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  add_gnodes(gen, gnodes::pulse_min_gnodes(cryptonote::FAKECHAIN));
  gen.add_n_blocks(40); // Chain genereator will generate blocks via Pulse quorums

  gyuanx_register_callback(events, "check_pulse_blocks", [](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_pulse_blocks");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    cryptonote::block top_block = c.get_blockchain_storage().get_db().get_block(top_hash);
    CHECK_TEST_CONDITION(cryptonote::block_has_pulse_components(top_block));
    return true;
  });
  return true;
}

bool gyuanx_pulse_fallback_to_pow_and_back::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  add_gnodes(gen, gnodes::pulse_min_gnodes(cryptonote::FAKECHAIN));
  gen.create_and_add_next_block();

  gen.add_event_msg("Deregister 1 node, we now have insufficient nodes for Pulse");
  {
    const auto deregister_pub_key_1 = gen.top_quorum().obligations->workers[0];
    cryptonote::transaction tx =
        gen.create_and_add_state_change_tx(gnodes::new_state::deregister, deregister_pub_key_1);
    gen.create_and_add_next_block({tx});
  }

  gen.add_event_msg("Check that we accept a PoW block");
  {
    gyuanx_create_block_params block_params = gen.next_block_params();
    block_params.type                     = gyuanx_create_block_type::miner;

    gyuanx_blockchain_entry entry = {};
    bool created = gen.create_block(entry, block_params, {});
    assert(created);
    gen.add_block(entry, true, "Can add a Miner block, we have insufficient nodes for Pulse so we fall back to PoW blocks.");
  }

  gyuanx_register_callback(events, "check_no_pulse_quorum_exists", [](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_no_pulse_quorum_exists");
    const auto quorum = c.get_quorum(gnodes::quorum_type::pulse, c.get_current_blockchain_height() - 1, false, nullptr);
    CHECK_TEST_CONDITION(quorum.get() == nullptr);
    return true;
  });

  gen.add_event_msg("Re-register a node, allowing us to re-enter Pulse");
  {
    cryptonote::transaction registration_txs = gen.create_and_add_registration_tx(gen.first_miner());
    gen.create_and_add_next_block({registration_txs});
    gen.add_n_blocks(10);
  }

  return true;
}

bool gyuanx_pulse_chain_split::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();
  add_gnodes(gen, std::max(gnodes::pulse_min_gnodes(cryptonote::FAKECHAIN), gnodes::CHECKPOINT_QUORUM_SIZE));

  gen.create_and_add_next_block();

  gen.add_event_msg("Diverge the two chains");
  gyuanx_chain_generator fork = gen;
  gen.create_and_add_next_block();
  fork.create_and_add_next_block();

  gen.add_event_msg(
      "On both chains add equivalent blocks in tandem (to avoid one chain attaining greater chain weight before the "
      "other) and add checkpoint causing reorg");
  for (;;)
  {
    gen.create_and_add_next_block();
    fork.create_and_add_next_block();
    std::shared_ptr<const gnodes::quorum> fork_quorum = fork.get_quorum(gnodes::quorum_type::checkpointing, fork.height());
    if (fork_quorum && fork_quorum->validators.size()) break;
  }
  fork.add_gnode_checkpoint(fork.height(), gnodes::CHECKPOINT_MIN_VOTES);
  gen.create_and_add_next_block();
  fork.create_and_add_next_block();

  crypto::hash const fork_top_hash = cryptonote::get_block_hash(fork.top().block);
  gyuanx_register_callback(events, "check_reorganized_to_pulse_chain_with_checkpoints", [fork_top_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_reorganized_to_pulse_chain_with_checkpoints");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(fork_top_hash, top_hash);
    return true;
  });
  return true;
}

// Same as gyuanx_pulse_chain_split but, we don't use checkpoints. We rely on
// Pulse chain weight to switch over.
bool gyuanx_pulse_chain_split_with_no_checkpoints::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = gyuanx_generate_sequential_hard_fork_table();
  gyuanx_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();
  add_gnodes(gen, std::max(gnodes::pulse_min_gnodes(cryptonote::FAKECHAIN), gnodes::CHECKPOINT_QUORUM_SIZE));

  gen.create_and_add_next_block();

  gen.add_event_msg("Diverge the two chains");
  gyuanx_chain_generator fork = gen;
  gen.create_and_add_next_block();
  fork.create_and_add_next_block();

  fork.create_and_add_next_block();
  crypto::hash const fork_top_hash = cryptonote::get_block_hash(fork.top().block);
  gyuanx_register_callback(events, "check_reorganized_to_pulse_chain_with_no_checkpoints", [fork_top_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_reorganized_to_pulse_chain_with_no_checkpoints");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(fork_top_hash, top_hash);
    return true;
  });
  return true;
}
