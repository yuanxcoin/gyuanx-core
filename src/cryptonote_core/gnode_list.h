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

#pragma once

#include <mutex>
#include <shared_mutex>
#include <string_view>
#include "serialization/serialization.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_core/gnode_rules.h"
#include "cryptonote_core/gnode_voting.h"
#include "cryptonote_core/gnode_quorum_cop.h"
#include "common/util.h"

namespace cryptonote
{
class Blockchain;
class BlockchainDB;
struct checkpoint_t;
}; // namespace cryptonote

namespace gnodes
{
  constexpr uint64_t INVALID_HEIGHT = static_cast<uint64_t>(-1);

  GYUANX_RPC_DOC_INTROSPECT
  struct participation_entry
  {
    bool is_pulse   = false;
    uint64_t height = INVALID_HEIGHT;
    bool voted      = true;

    struct
    {
      uint8_t round = 0;
    } pulse;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(height);
      KV_SERIALIZE(voted);
      KV_SERIALIZE(is_pulse);
      if (this_ref.is_pulse)
      {
        KV_SERIALIZE_N(pulse.round, "pulse_round");
      }
    END_KV_SERIALIZE_MAP()
  };

  struct participation_history
  {
    std::array<participation_entry, QUORUM_VOTE_CHECK_COUNT> array;
    size_t                                                   write_index;

    void reset() { write_index = 0; }

    void add(participation_entry const &entry)
    {
      size_t real_write_index = write_index % array.size();
      array[real_write_index] = entry;
      write_index++;
    }

    participation_entry       *begin()       { return array.data(); }
    participation_entry       *end()         { return array.data() + std::min(array.size(), write_index); }
    participation_entry const *begin() const { return array.data(); }
    participation_entry const *end()   const { return array.data() + std::min(array.size(), write_index); }
  };

  struct proof_info
  {
    participation_history pulse_participation{};
    participation_history checkpoint_participation{};

    uint64_t timestamp           = 0; // The actual time we last received an uptime proof (serialized)
    uint64_t effective_timestamp = 0; // Typically the same, but on recommissions it is set to the recommission block time to fend off instant obligation checks
    std::array<std::pair<uint32_t, uint64_t>, 2> public_ips = {}; // (not serialized)

    bool storage_server_reachable               = true;
    uint64_t storage_server_reachable_timestamp = 0;

    // Unlike all of the above (except for timestamp), these values *do* get serialized
    uint32_t public_ip        = 0;
    uint16_t storage_port     = 0;
    uint16_t storage_lmq_port = 0;
    uint16_t quorumnet_port   = 0;
    std::array<uint16_t, 3> version{{0,0,0}};
    crypto::ed25519_public_key pubkey_ed25519 = crypto::ed25519_public_key::null();

    // Derived from pubkey_ed25519, not serialized
    crypto::x25519_public_key pubkey_x25519 = crypto::x25519_public_key::null();

    // Updates pubkey_ed25519 to the given key, re-deriving the x25519 key if it actually changes
    // (does nothing if the key is the same as the current value).  If x25519 derivation fails then
    // both pubkeys are set to null.
    void update_pubkey(const crypto::ed25519_public_key &pk);

    // Called to update data received from a proof is received, updating values in the local object.
    // Returns true if serializable data is changed (in which case `store()` should be called).
    // Note that this does not update the m_x25519_to_pub map if the x25519 key changes (that's the
    // caller's responsibility).
    bool update(uint64_t ts, uint32_t ip, uint16_t s_port, uint16_t s_lmq_port, uint16_t q_port, std::array<uint16_t, 3> ver, const crypto::ed25519_public_key &pk_ed, const crypto::x25519_public_key &pk_x2);

    // Stores this record in the database.
    void store(const crypto::public_key &pubkey, cryptonote::Blockchain &blockchain);
  };

  struct pulse_sort_key
  {
    uint64_t last_height_validating_in_quorum = 0;
    uint8_t quorum_index                      = 0;

    bool operator==(pulse_sort_key const &other) const
    {
      return last_height_validating_in_quorum == other.last_height_validating_in_quorum && quorum_index == other.quorum_index;
    }
    bool operator<(pulse_sort_key const &other) const
    {
      bool result = std::make_pair(last_height_validating_in_quorum, quorum_index) < std::make_pair(other.last_height_validating_in_quorum, other.quorum_index);
      return result;
    }

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(last_height_validating_in_quorum)
      FIELD(quorum_index)
    END_SERIALIZE()
  };

  struct gnode_info // registration information
  {
    enum class version_t : uint8_t
    {
      v0_checkpointing,               // versioning reset in 4.0.0 (data structure storage changed)
      v1_add_registration_hf_version,
      v2_ed25519,
      v3_quorumnet,
      v4_noproofs,
      v5_pulse_recomm_credit,
      v6_reassign_sort_keys,
      _count
    };

    struct contribution_t
    {
      enum class version_t : uint8_t {
        v0,

        _count
      };

      version_t          version{version_t::v0};
      crypto::public_key key_image_pub_key{};
      crypto::key_image  key_image{};
      uint64_t           amount = 0;

      contribution_t() = default;
      contribution_t(version_t version, const crypto::public_key &pubkey, const crypto::key_image &key_image, uint64_t amount)
        : version{version}, key_image_pub_key{pubkey}, key_image{key_image}, amount{amount} {}

      BEGIN_SERIALIZE_OBJECT()
        ENUM_FIELD(version, version < version_t::_count)
        FIELD(key_image_pub_key)
        FIELD(key_image)
        VARINT_FIELD(amount)
      END_SERIALIZE()
    };

    struct contributor_t
    {
      uint8_t  version = 0;
      uint64_t amount = 0;
      uint64_t reserved = 0;
      cryptonote::account_public_address address{};
      std::vector<contribution_t> locked_contributions;

      contributor_t() = default;
      contributor_t(uint64_t reserved_, const cryptonote::account_public_address& address_) : reserved(reserved_), address(address_)
      {
        *this    = {};
        reserved = reserved_;
        address  = address_;
      }

      BEGIN_SERIALIZE_OBJECT()
        VARINT_FIELD(version)
        VARINT_FIELD(amount)
        VARINT_FIELD(reserved)
        FIELD(address)
        FIELD(locked_contributions)
      END_SERIALIZE()
    };

    uint64_t                           registration_height = 0;
    uint64_t                           requested_unlock_height = 0;
    // block_height and transaction_index are to record when the service node last received a reward.
    uint64_t                           last_reward_block_height = 0;
    uint32_t                           last_reward_transaction_index = 0;
    uint32_t                           decommission_count = 0; // How many times this service node has been decommissioned
    int64_t                            active_since_height = 0; // if decommissioned: equal to the *negative* height at which you became active before the decommission
    uint64_t                           last_decommission_height = 0; // The height at which the last (or current!) decommissioning started, or 0 if never decommissioned
    int64_t                            recommission_credit = DECOMMISSION_INITIAL_CREDIT; // The number of blocks of credit you started with or kept when you were last activated (i.e. as of `active_since_height`)
    std::vector<contributor_t>         contributors;
    uint64_t                           total_contributed = 0;
    uint64_t                           total_reserved = 0;
    uint64_t                           staking_requirement = 0;
    uint64_t                           portions_for_operator = 0;
    swarm_id_t                         swarm_id = 0;
    cryptonote::account_public_address operator_address{};
    uint64_t                           last_ip_change_height = 0; // The height of the last quorum penalty for changing IPs
    version_t                          version = tools::enum_top<version_t>;
    uint8_t                            registration_hf_version = 0;
    pulse_sort_key                     pulse_sorter;

    gnode_info() = default;
    bool is_fully_funded() const { return total_contributed >= staking_requirement; }
    bool is_decommissioned() const { return active_since_height < 0; }
    bool is_active() const { return is_fully_funded() && !is_decommissioned(); }

    bool can_transition_to_state(uint8_t hf_version, uint64_t block_height, new_state proposed_state) const;
    bool can_be_voted_on        (uint64_t block_height) const;
    size_t total_num_locked_contributions() const;

    BEGIN_SERIALIZE_OBJECT()
      ENUM_FIELD(version, version < version_t::_count)
      VARINT_FIELD(registration_height)
      VARINT_FIELD(requested_unlock_height)
      VARINT_FIELD(last_reward_block_height)
      VARINT_FIELD(last_reward_transaction_index)
      VARINT_FIELD(decommission_count)
      VARINT_FIELD(active_since_height)
      VARINT_FIELD(last_decommission_height)
      FIELD(contributors)
      VARINT_FIELD(total_contributed)
      VARINT_FIELD(total_reserved)
      VARINT_FIELD(staking_requirement)
      VARINT_FIELD(portions_for_operator)
      FIELD(operator_address)
      VARINT_FIELD(swarm_id)
      if (version < version_t::v4_noproofs) {
        uint32_t fake_ip = 0;
        uint16_t fake_port = 0;
        VARINT_FIELD_N("public_ip", fake_ip)
        VARINT_FIELD_N("storage_port", fake_port)
      }
      VARINT_FIELD(last_ip_change_height)
      if (version >= version_t::v1_add_registration_hf_version)
        VARINT_FIELD(registration_hf_version);
      if (version >= version_t::v2_ed25519 && version < version_t::v4_noproofs) {
        crypto::ed25519_public_key fake_pk = crypto::ed25519_public_key::null();
        FIELD_N("pubkey_ed25519", fake_pk)
        if (version >= version_t::v3_quorumnet) {
          uint16_t fake_port = 0;
          VARINT_FIELD_N("quorumnet_port", fake_port)
        }
      }
      if (version >= version_t::v5_pulse_recomm_credit)
      {
        VARINT_FIELD(recommission_credit)
        FIELD(pulse_sorter)
      }
    END_SERIALIZE()
  };

  using pubkey_and_sninfo     =          std::pair<crypto::public_key, std::shared_ptr<const gnode_info>>;
  using gnodes_infos_t = std::unordered_map<crypto::public_key, std::shared_ptr<const gnode_info>>;

  struct gnode_pubkey_info
  {
    crypto::public_key pubkey;
    std::shared_ptr<const gnode_info> info;

    gnode_pubkey_info() = default;
    gnode_pubkey_info(const pubkey_and_sninfo &pair) : pubkey{pair.first}, info{pair.second} {}

    BEGIN_SERIALIZE_OBJECT()
      FIELD(pubkey)
      if (Archive::is_deserializer)
        info = std::make_shared<gnode_info>();
      FIELD_N("info", const_cast<gnode_info &>(*info))
    END_SERIALIZE()
  };

  struct key_image_blacklist_entry
  {
    enum struct version_t : uint8_t { version_0, version_1_serialize_amount, count, };
    version_t           version{version_t::version_1_serialize_amount};
    crypto::key_image key_image;
    uint64_t          unlock_height = 0;
    uint64_t          amount        = 0;

    key_image_blacklist_entry() = default;
    key_image_blacklist_entry(version_t version, const crypto::key_image &key_image, uint64_t unlock_height, uint64_t amount)
  : version{version}, key_image{key_image}, unlock_height{unlock_height}, amount(amount) {}

    bool operator==(const key_image_blacklist_entry &other) const { return key_image == other.key_image; }
    bool operator==(const crypto::key_image &image) const { return key_image == image; }

    BEGIN_SERIALIZE()
      ENUM_FIELD(version, version < version_t::count)
      FIELD(key_image)
      VARINT_FIELD(unlock_height)
      if (version >= version_t::version_1_serialize_amount)
        VARINT_FIELD(amount)
    END_SERIALIZE()
  };

  struct payout_entry
  {
    cryptonote::account_public_address address;
    uint64_t portions;

    constexpr bool operator==(const payout_entry& x) const { return portions == x.portions && address == x.address; }
  };

  struct payout
  {
    crypto::public_key key;
    std::vector<payout_entry> payouts;
  };

  /// Collection of keys used by a service node
  struct gnode_keys {
    /// The service node key pair used for registration-related data on the chain; is
    /// curve25519-based but with Monero-specific changes that make it useless for external tools
    /// supporting standard ed25519 or x25519 keys.
    /// TODO(gyuanx) - eventually drop this key and just do everything with the ed25519 key.
    crypto::secret_key key;
    crypto::public_key pub;

    /// A secondary SN key pair used for ancillary operations by tools (e.g. libsodium) that rely
    /// on standard cryptography keypair signatures.
    crypto::ed25519_secret_key key_ed25519;
    crypto::ed25519_public_key pub_ed25519;

    /// A x25519 key computed from the ed25519 key, above, that is used for SN-to-SN encryption.
    /// (Unlike this above two keys this is not stored to disk; it is generated on the fly from the
    /// ed25519 key).
    crypto::x25519_secret_key key_x25519;
    crypto::x25519_public_key pub_x25519;
  };

  class gnode_list
    : public cryptonote::BlockAddedHook,
      public cryptonote::BlockchainDetachedHook,
      public cryptonote::InitHook,
      public cryptonote::ValidateMinerTxHook,
      public cryptonote::AltBlockAddedHook
  {
  public:
    explicit gnode_list(cryptonote::Blockchain& blockchain);
    // non-copyable:
    gnode_list(const gnode_list &) = delete;
    gnode_list &operator=(const gnode_list &) = delete;

    bool block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs, cryptonote::checkpoint_t const *checkpoint) override;
    void blockchain_detached(uint64_t height, bool by_pop_blocks) override;
    void init() override;
    bool validate_miner_tx(cryptonote::block const &block, cryptonote::block_reward_parts const &base_reward) const override;
    bool alt_block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs, cryptonote::checkpoint_t const *checkpoint) override;
    payout get_block_leader() const { std::lock_guard lock{m_sn_mutex}; return m_state.get_block_leader(); }
    bool is_gnode(const crypto::public_key& pubkey, bool require_active = true) const;
    bool is_key_image_locked(crypto::key_image const &check_image, uint64_t *unlock_height = nullptr, gnode_info::contribution_t *the_locked_contribution = nullptr) const;
    uint64_t height() const { return m_state.height; }

    /// Note(maxim): this should not affect thread-safety as the returned object is const
    ///
    /// For checkpointing, quorums are only generated when height % CHECKPOINT_INTERVAL == 0 (and
    /// the actual internal quorum used is for `height - REORG_SAFETY_BUFFER_BLOCKS_POST_HF12`, i.e.
    /// do no subtract off the buffer in advance).
    /// Similarly for blink (but on BLINK_QUORUM_INTERVAL, but without any buffer offset applied here).
    /// return: nullptr if the quorum is not cached in memory (pruned from memory).
    std::shared_ptr<const quorum> get_quorum(quorum_type type, uint64_t height, bool include_old = false, std::vector<std::shared_ptr<const quorum>> *alt_states = nullptr) const;
    bool                          get_quorum_pubkey(quorum_type type, quorum_group group, uint64_t height, size_t quorum_index, crypto::public_key &key) const;

    size_t get_gnode_count() const;
    std::vector<gnode_pubkey_info> get_gnode_list_state(const std::vector<crypto::public_key> &gnode_pubkeys = {}) const;
    const std::vector<key_image_blacklist_entry> &get_blacklisted_key_images() const { return m_state.key_image_blacklist; }

    /// Accesses a proof with the required lock held; used to extract needed proof values.  Func
    /// should be callable with a single `const proof_info &` argument.  If there is no proof info
    /// at all for the given pubkey then Func will not be called.
    template <typename Func>
    void access_proof(const crypto::public_key &pubkey, Func f) const {
      std::unique_lock lock{m_sn_mutex};
      auto it = proofs.find(pubkey);
      if (it != proofs.end())
        f(it->second);
    }

    /// Returns the (monero curve) pubkey associated with a x25519 pubkey.  Returns a null public
    /// key if not found.  (Note: this is just looking up the association, not derivation).
    crypto::public_key get_pubkey_from_x25519(const crypto::x25519_public_key &x25519) const;

    /// Initializes the x25519 map from current pubkey state; called during initialization
    void initialize_x25519_map();

    /// Remote SN lookup address function for LokiMQ: given a string_view of a x25519 pubkey, this
    /// returns that service node's quorumnet contact information, if we have it, else empty string.
    std::string remote_lookup(std::string_view x25519_pk);

    /// Does something read-only for each registered service node in the range of pubkeys.  The SN
    /// lock is held while iterating, so the "something" should be quick.  Func should take
    /// arguments:
    ///     (const crypto::public_key&, const gnode_info&, const proof_info&)
    /// Unknown public keys are skipped.
    template <typename It, typename Func>
    void for_each_gnode_info_and_proof(It begin, It end, Func f) const {
      static const proof_info empty_proof{};
      std::lock_guard lock{m_sn_mutex};
      for (auto sni_end = m_state.gnodes_infos.end(); begin != end; ++begin) {
        auto it = m_state.gnodes_infos.find(*begin);
        if (it != sni_end) {
          auto pit = proofs.find(it->first);
          f(it->first, *it->second, (pit != proofs.end() ? pit->second : empty_proof));
        }
      }
    }

    /// Copies x25519 pubkeys (as strings) of all currently active SNs into the given output iterator
    template <typename OutputIt>
    void copy_active_x25519_pubkeys(OutputIt out) const {
      std::lock_guard lock{m_sn_mutex};
      for (const auto& pk_info : m_state.gnodes_infos) {
        if (!pk_info.second->is_active())
          continue;
        auto it = proofs.find(pk_info.first);
        if (it == proofs.end())
          continue;
        if (const auto& x2_pk = it->second.pubkey_x25519)
          *out++ = std::string{reinterpret_cast<const char*>(&x2_pk), sizeof(x2_pk)};
      }
    }

    std::vector<pubkey_and_sninfo> active_gnodes_infos() const {
      return m_state.active_gnodes_infos();
    }

    void set_my_gnode_keys(const gnode_keys *keys);
    void set_quorum_history_storage(uint64_t hist_size); // 0 = none (default), 1 = unlimited, N = # of blocks
    bool store();

    /// Record public ip and storage port and add them to the service node list
    cryptonote::NOTIFY_UPTIME_PROOF::request generate_uptime_proof(uint32_t public_ip,
                                                                   uint16_t storage_port,
                                                                   uint16_t storage_lmq_port,
                                                                   uint16_t quorumnet_port) const;
    bool handle_uptime_proof(cryptonote::NOTIFY_UPTIME_PROOF::request const &proof, bool &my_uptime_proof_confirmation, crypto::x25519_public_key &x25519_pkey);

    void record_checkpoint_participation(crypto::public_key const &pubkey, uint64_t height, bool participated);

    // Called every hour to remove proofs for expired SNs from memory and the database.
    void cleanup_proofs();

    bool set_storage_server_peer_reachable(crypto::public_key const &pubkey, bool value);

    struct quorum_for_serialization
    {
      uint8_t        version;
      uint64_t       height;
      quorum         quorums[tools::enum_count<quorum_type>];

      BEGIN_SERIALIZE()
        FIELD(version)
        FIELD(height)
        FIELD_N("obligations_quorum", quorums[static_cast<uint8_t>(quorum_type::obligations)])
        FIELD_N("checkpointing_quorum", quorums[static_cast<uint8_t>(quorum_type::checkpointing)])
      END_SERIALIZE()
    };

    struct state_serialized
    {
      enum struct version_t : uint8_t { version_0, version_1_serialize_hash, count, };
      static version_t get_version(uint8_t /*hf_version*/) { return version_t::version_1_serialize_hash; }

      version_t                              version;
      uint64_t                               height;
      std::vector<gnode_pubkey_info>  infos;
      std::vector<key_image_blacklist_entry> key_image_blacklist;
      quorum_for_serialization               quorums;
      bool                                   only_stored_quorums;
      crypto::hash                           block_hash;

      BEGIN_SERIALIZE()
        ENUM_FIELD(version, version < version_t::count)
        VARINT_FIELD(height)
        FIELD(infos)
        FIELD(key_image_blacklist)
        FIELD(quorums)
        FIELD(only_stored_quorums)

        if (version >= version_t::version_1_serialize_hash)
          FIELD(block_hash);
      END_SERIALIZE()
    };

    struct data_for_serialization
    {
      enum struct version_t : uint8_t { version_0, count, };
      static version_t get_version(uint8_t /*hf_version*/) { return version_t::version_0; }

      version_t version;
      std::vector<quorum_for_serialization> quorum_states;
      std::vector<state_serialized>         states;
      void clear() { quorum_states.clear(); states.clear(); version = {}; }

      BEGIN_SERIALIZE()
        ENUM_FIELD(version, version < version_t::count)
        FIELD(quorum_states)
        FIELD(states)
      END_SERIALIZE()
    };

    struct state_t;
    using state_set = std::set<state_t, std::less<>>;
    using block_height = uint64_t;
    struct state_t
    {
      crypto::hash                           block_hash{crypto::null_hash};
      bool                                   only_loaded_quorums{false};
      gnodes_infos_t                  gnodes_infos;
      std::vector<key_image_blacklist_entry> key_image_blacklist;
      block_height                           height{0};
      mutable quorum_manager                 quorums;          // Mutable because we are allowed to (and need to) change it via std::set iterator
      gnode_list*                     sn_list;

      state_t(gnode_list* snl) : sn_list{snl} {}
      state_t(gnode_list* snl, state_serialized &&state);

      friend bool operator<(const state_t &a, const state_t &b) { return a.height < b.height; }
      friend bool operator<(const state_t &s, block_height h)   { return s.height < h; }
      friend bool operator<(block_height h, const state_t &s)   { return        h < s.height; }

      std::vector<pubkey_and_sninfo>  active_gnodes_infos() const;
      std::vector<pubkey_and_sninfo>  decommissioned_gnodes_infos() const; // return: All nodes that are fully funded *and* decommissioned.
      std::vector<crypto::public_key> get_expired_nodes(cryptonote::BlockchainDB const &db, cryptonote::network_type nettype, uint8_t hf_version, uint64_t block_height) const;
      void update_from_block(
          cryptonote::BlockchainDB const &db,
          cryptonote::network_type nettype,
          state_set const &state_history,
          state_set const &state_archive,
          std::unordered_map<crypto::hash, state_t> const &alt_states,
          const cryptonote::block& block,
          const std::vector<cryptonote::transaction>& txs,
          const gnode_keys *my_keys);

      // Returns true if there was a registration:
      bool process_registration_tx(cryptonote::network_type nettype, cryptonote::block const &block, const cryptonote::transaction& tx, uint32_t index, const gnode_keys *my_keys);
      // Returns true if there was a successful contribution that fully funded a service node:
      bool process_contribution_tx(cryptonote::network_type nettype, cryptonote::block const &block, const cryptonote::transaction& tx, uint32_t index);
      // Returns true if a service node changed state (deregistered, decommissioned, or recommissioned)
      bool process_state_change_tx(
          state_set const &state_history,
          state_set const &state_archive,
          std::unordered_map<crypto::hash, state_t> const &alt_states,
          cryptonote::network_type nettype,
          const cryptonote::block &block,
          const cryptonote::transaction& tx,
          const gnode_keys *my_keys);
      bool process_key_image_unlock_tx(cryptonote::network_type nettype, uint64_t block_height, const cryptonote::transaction &tx);
      payout get_block_leader() const;
      payout get_block_producer(uint8_t pulse_round) const;
    };

    // Can be set to true (via --dev-allow-local-ips) for debugging a new testnet on a local private network.
    bool debug_allow_local_ips = false;

  private:
    // Note(maxim): private methods don't have to be protected the mutex
    bool m_rescanning = false; /* set to true when doing a rescan so we know not to reset proofs */
    void process_block(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs);
    void record_pulse_participation(crypto::public_key const &pubkey, uint64_t height, uint8_t round, bool participated);

    // Verify block against Service Node state that has just been called with 'state.update_from_block(block)'.
    bool verify_block(const cryptonote::block& block, bool alt_block, cryptonote::checkpoint_t const *checkpoint);

    void reset(bool delete_db_entry = false);
    bool load(uint64_t current_height);

    mutable std::recursive_mutex  m_sn_mutex;
    cryptonote::Blockchain&       m_blockchain;
    const gnode_keys      *m_gnode_keys;
    uint64_t                      m_store_quorum_history = 0;
    mutable std::shared_mutex     m_x25519_map_mutex;

    /// Maps x25519 pubkeys to registration pubkeys + last block seen value (used for expiry)
    std::unordered_map<crypto::x25519_public_key, std::pair<crypto::public_key, time_t>> x25519_to_pub;
    time_t x25519_map_last_pruned = 0;
    std::unordered_map<crypto::public_key, proof_info> proofs;

    struct quorums_by_height
    {
      quorums_by_height() = default;
      quorums_by_height(uint64_t height, quorum_manager quorums) : height(height), quorums(std::move(quorums)) {}
      uint64_t       height;
      quorum_manager quorums;
    };

    struct
    {
      std::deque<quorums_by_height>             old_quorum_states; // Store all old quorum history only if run with --store-full-quorum-history
      state_set                                 state_history; // Store state_t's from MIN(2nd oldest checkpoint | height - DEFAULT_SHORT_TERM_STATE_HISTORY) up to the block height
      state_set                                 state_archive; // Store state_t's where ((height < m_state_history.first()) && (height % STORE_LONG_TERM_STATE_INTERVAL))
      std::unordered_map<crypto::hash, state_t> alt_state;
      bool                                      state_added_to_archive;
      data_for_serialization                    cache_long_term_data;
      data_for_serialization                    cache_short_term_data;
      std::string                               cache_data_blob;
    } m_transient = {};

    state_t m_state; // NOTE: Not in m_transient due to the non-trivial constructor. We can't blanket initialise using = {}; needs to be reset in ::reset(...) manually
  };

  struct staking_components
  {
    crypto::public_key                             gnode_pubkey;
    cryptonote::account_public_address             address;
    uint64_t                                       transferred;
    crypto::secret_key                             tx_key;
    std::vector<gnode_info::contribution_t> locked_contributions;
  };
  bool tx_get_staking_components            (cryptonote::transaction_prefix const &tx_prefix, staking_components *contribution, crypto::hash const &txid);
  bool tx_get_staking_components            (cryptonote::transaction const &tx, staking_components *contribution);
  bool tx_get_staking_components_and_amounts(cryptonote::network_type nettype, uint8_t hf_version, cryptonote::transaction const &tx, uint64_t block_height, staking_components *contribution);

  struct contributor_args_t
  {
    bool                                            success;
    std::vector<cryptonote::account_public_address> addresses;
    std::vector<uint64_t>                           portions;
    uint64_t                                        portions_for_operator;
    std::string                                     err_msg; // if (success == false), this is set to the err msg otherwise empty
  };

  bool     is_registration_tx   (cryptonote::network_type nettype, uint8_t hf_version, const cryptonote::transaction& tx, uint64_t block_timestamp, uint64_t block_height, uint32_t index, crypto::public_key& key, gnode_info& info);
  bool     reg_tx_extract_fields(const cryptonote::transaction& tx, contributor_args_t &contributor_args, uint64_t& expiration_timestamp, crypto::public_key& gnode_key, crypto::signature& signature, crypto::public_key& tx_pub_key);
  uint64_t offset_testing_quorum_height(quorum_type type, uint64_t height);

  contributor_args_t convert_registration_args(cryptonote::network_type nettype,
                                               const std::vector<std::string> &args,
                                               uint64_t staking_requirement,
                                               uint8_t hf_version);

  // validate_contributors_* functions throws invalid_contributions exception
  struct invalid_contributions : std::invalid_argument { using std::invalid_argument::invalid_argument; };
  void validate_contributor_args(uint8_t hf_version, contributor_args_t const &contributor_args);
  void validate_contributor_args_signature(contributor_args_t const &contributor_args, uint64_t const expiration_timestamp, crypto::public_key const &gnode_key, crypto::signature const &signature);

  bool make_registration_cmd(cryptonote::network_type nettype,
      uint8_t hf_version,
      uint64_t staking_requirement,
      const std::vector<std::string>& args,
      const gnode_keys &keys,
      std::string &cmd,
      bool make_friendly);

  gnodes::quorum generate_pulse_quorum(cryptonote::network_type nettype,
                                              crypto::public_key const &leader,
                                              uint8_t hf_version,
                                              std::vector<pubkey_and_sninfo> const &active_snode_list,
                                              std::vector<crypto::hash> const &pulse_entropy,
                                              uint8_t pulse_round);

  // The pulse entropy is generated for the next block after the top_block passed in.
  std::vector<crypto::hash> get_pulse_entropy_for_next_block(cryptonote::BlockchainDB const &db, cryptonote::block const &top_block, uint8_t pulse_round);
  std::vector<crypto::hash> get_pulse_entropy_for_next_block(cryptonote::BlockchainDB const &db, crypto::hash const &top_hash, uint8_t pulse_round);
  // Same as above, but uses the current blockchain top block and defaults to round 0 if not
  // specified.
  std::vector<crypto::hash> get_pulse_entropy_for_next_block(cryptonote::BlockchainDB const &db, uint8_t pulse_round = 0);

  payout gnode_info_to_payout(crypto::public_key const &key, gnode_info const &info);

  const static payout_entry null_payout_entry = {cryptonote::null_address, STAKING_PORTIONS};
  const static payout null_payout             = {crypto::null_pkey, {null_payout_entry}};
}
