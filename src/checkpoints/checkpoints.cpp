// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Gyuanx Project
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

#include "checkpoints.h"

#include "epee/string_tools.h"
#include "epee/storages/portable_storage_template_helper.h" // epee json include
#include "epee/serialization/keyvalue_serialization.h"
#include "cryptonote_core/gnode_rules.h"
#include <vector>
#include "blockchain_db/blockchain_db.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

#include "common/gyuanx_integration_test_hooks.h"
#include "common/gyuanx.h"
#include "common/file.h"
#include "common/hex.h"

#undef GYUANX_DEFAULT_LOG_CATEGORY
#define GYUANX_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  bool checkpoint_t::check(crypto::hash const &hash) const
  {
    bool result = block_hash == hash;
    if (result) MINFO   ("CHECKPOINT PASSED FOR HEIGHT " << height << " " << block_hash);
    else        MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH " << block_hash << "GIVEN HASH: " << hash);
    return result;
  }

  height_to_hash const HARDCODED_MAINNET_CHECKPOINTS[] =
  {
    {0,      "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3"},
  };

  crypto::hash get_newest_hardcoded_checkpoint(cryptonote::network_type nettype, uint64_t *height)
  {
    crypto::hash result = crypto::null_hash;
    *height = 0;
    if (nettype != MAINNET && nettype != TESTNET)
      return result;

    if (nettype == MAINNET)
    {
      uint64_t last_index         = gyuanx::array_count(HARDCODED_MAINNET_CHECKPOINTS) - 1;
      height_to_hash const &entry = HARDCODED_MAINNET_CHECKPOINTS[last_index];

      if (tools::hex_to_type(entry.hash, result))
        *height = entry.height;
    }
    return result;
  }

  bool load_checkpoints_from_json(const fs::path& json_hashfile_fullpath, std::vector<height_to_hash>& checkpoint_hashes)
  {
    if (std::error_code ec; !fs::exists(json_hashfile_fullpath, ec))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    height_to_hash_json hashes;
    if (std::string contents;
        !tools::slurp_file(json_hashfile_fullpath, contents) ||
        !epee::serialization::load_t_from_json(hashes, contents))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }

    checkpoint_hashes = std::move(hashes.hashlines);
    return true;
  }

  bool checkpoints::get_checkpoint(uint64_t height, checkpoint_t &checkpoint) const
  {
    try
    {
      auto guard = db_rtxn_guard(m_db);
      return m_db->get_block_checkpoint(height, checkpoint);
    }
    catch (const std::exception &e)
    {
      MERROR("Get block checkpoint from DB failed at height: " << height << ", what = " << e.what());
      return false;
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r         = tools::hex_to_type(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    checkpoint_t checkpoint = {};
    if (get_checkpoint(height, checkpoint))
    {
      crypto::hash const &curr_hash = checkpoint.block_hash;
      CHECK_AND_ASSERT_MES(h == curr_hash, false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    else
    {
      checkpoint.type       = checkpoint_type::hardcoded;
      checkpoint.height     = height;
      checkpoint.block_hash = h;
      r                     = update_checkpoint(checkpoint);
    }

    return r;
  }
  bool checkpoints::update_checkpoint(checkpoint_t const &checkpoint)
  {
    // NOTE(gyuanx): Assumes checkpoint is valid
    bool result        = true;
    bool batch_started = false;
    try
    {
      batch_started = m_db->batch_start();
      m_db->update_block_checkpoint(checkpoint);
    }
    catch (const std::exception& e)
    {
      MERROR("Failed to add checkpoint with hash: " << checkpoint.block_hash << " at height: " << checkpoint.height << ", what = " << e.what());
      result = false;
    }

    if (batch_started)
      m_db->batch_stop();
    return result;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs, checkpoint_t const *checkpoint)
  {
    uint64_t const height = get_block_height(block);
    if (height < gnodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL || block.major_version < network_version_12_checkpointing)
      return true;

    uint64_t end_cull_height = 0;
    {
      checkpoint_t immutable_checkpoint;
      if (m_db->get_immutable_checkpoint(&immutable_checkpoint, height + 1))
        end_cull_height = immutable_checkpoint.height;
    }
    uint64_t start_cull_height = (end_cull_height < gnodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL)
                                     ? 0
                                     : end_cull_height - gnodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL;

    if ((start_cull_height % gnodes::CHECKPOINT_INTERVAL) > 0)
      start_cull_height += (gnodes::CHECKPOINT_INTERVAL - (start_cull_height % gnodes::CHECKPOINT_INTERVAL));

    m_last_cull_height = std::max(m_last_cull_height, start_cull_height);
    auto guard         = db_wtxn_guard(m_db);
    for (; m_last_cull_height < end_cull_height; m_last_cull_height += gnodes::CHECKPOINT_INTERVAL)
    {
      if (m_last_cull_height % gnodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL == 0)
        continue;

      try
      {
        m_db->remove_block_checkpoint(m_last_cull_height);
      }
      catch (const std::exception &e)
      {
        MERROR("Pruning block checkpoint on block added failed non-trivially at height: " << m_last_cull_height << ", what = " << e.what());
      }
    }

    if (checkpoint)
        update_checkpoint(*checkpoint);

    return true;
  }
  //---------------------------------------------------------------------------
  void checkpoints::blockchain_detached(uint64_t height, bool /*by_pop_blocks*/)
  {
    m_last_cull_height = std::min(m_last_cull_height, height);

    checkpoint_t top_checkpoint;
    auto guard = db_wtxn_guard(m_db);
    if (m_db->get_top_checkpoint(top_checkpoint))
    {
      uint64_t start_height = top_checkpoint.height;
      for (size_t delete_height = start_height;
           delete_height >= height && delete_height >= gnodes::CHECKPOINT_INTERVAL;
           delete_height -= gnodes::CHECKPOINT_INTERVAL)
      {
        try
        {
          m_db->remove_block_checkpoint(delete_height);
        }
        catch (const std::exception &e)
        {
          MERROR("Remove block checkpoint on detach failed non-trivially at height: " << delete_height << ", what = " << e.what());
        }
      }
    }
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    uint64_t top_checkpoint_height = 0;
    checkpoint_t top_checkpoint;
    if (m_db->get_top_checkpoint(top_checkpoint))
      top_checkpoint_height = top_checkpoint.height;

    return height <= top_checkpoint_height;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool* is_a_checkpoint, bool *gnode_checkpoint) const
  {
    checkpoint_t checkpoint;
    bool found = get_checkpoint(height, checkpoint);
    if (is_a_checkpoint) *is_a_checkpoint = found;
    if (gnode_checkpoint) *gnode_checkpoint = false;

    if(!found)
      return true;

    bool result = checkpoint.check(h);
    if (gnode_checkpoint)
      *gnode_checkpoint = (checkpoint.type == checkpoint_type::gnode);

    return result;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height, bool *gnode_checkpoint)
  {
    if (gnode_checkpoint)
      *gnode_checkpoint = false;

    if (0 == block_height)
      return false;

    {
      std::vector<checkpoint_t> const first_checkpoint = m_db->get_checkpoints_range(0, blockchain_height, 1);
      if (first_checkpoint.empty() || blockchain_height < first_checkpoint[0].height)
        return true;
    }

    checkpoint_t immutable_checkpoint;
    uint64_t immutable_height = 0;
    if (m_db->get_immutable_checkpoint(&immutable_checkpoint, blockchain_height))
    {
      immutable_height = immutable_checkpoint.height;
      if (gnode_checkpoint)
        *gnode_checkpoint = (immutable_checkpoint.type == checkpoint_type::gnode);
    }

    m_immutable_height = std::max(immutable_height, m_immutable_height);
    bool result        = block_height > m_immutable_height;
    return result;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    uint64_t result = 0;
    checkpoint_t top_checkpoint;
    if (m_db->get_top_checkpoint(top_checkpoint))
      result = top_checkpoint.height;

    return result;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::init(network_type nettype, BlockchainDB *db)
  {
    *this     = {};
    m_db      = db;
    m_nettype = nettype;

    if (db->is_read_only())
      return true;

#if !defined(GYUANX_ENABLE_INTEGRATION_TEST_HOOKS)
    if (nettype == MAINNET)
    {
      for (size_t i = 0; i < gyuanx::array_count(HARDCODED_MAINNET_CHECKPOINTS); ++i)
      {
        height_to_hash const &checkpoint = HARDCODED_MAINNET_CHECKPOINTS[i];
        ADD_CHECKPOINT(checkpoint.height, checkpoint.hash);
      }
    }
#endif

    return true;
  }

}

