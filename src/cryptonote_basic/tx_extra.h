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

#include "serialization/serialization.h"
#include "serialization/binary_archive.h"
#include "serialization/binary_utils.h"
#include "serialization/variant.h"
#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "cryptonote_basic.h"


namespace cryptonote {

constexpr size_t
  TX_EXTRA_PADDING_MAX_COUNT = 255,
  TX_EXTRA_NONCE_MAX_COUNT   = 255;

constexpr uint8_t
  TX_EXTRA_TAG_PADDING                    = 0x00,
  TX_EXTRA_TAG_PUBKEY                     = 0x01,
  TX_EXTRA_NONCE                          = 0x02,
  TX_EXTRA_MERGE_MINING_TAG               = 0x03,
  TX_EXTRA_TAG_ADDITIONAL_PUBKEYS         = 0x04,
  TX_EXTRA_TAG_SERVICE_NODE_REGISTER      = 0x70,
  TX_EXTRA_TAG_SERVICE_NODE_DEREG_OLD     = 0x71,
  TX_EXTRA_TAG_SERVICE_NODE_WINNER        = 0x72,
  TX_EXTRA_TAG_SERVICE_NODE_CONTRIBUTOR   = 0x73,
  TX_EXTRA_TAG_SERVICE_NODE_PUBKEY        = 0x74,
  TX_EXTRA_TAG_TX_SECRET_KEY              = 0x75,
  TX_EXTRA_TAG_TX_KEY_IMAGE_PROOFS        = 0x76,
  TX_EXTRA_TAG_TX_KEY_IMAGE_UNLOCK        = 0x77,
  TX_EXTRA_TAG_SERVICE_NODE_STATE_CHANGE  = 0x78,
  TX_EXTRA_TAG_BURN                       = 0x79,
  TX_EXTRA_TAG_GYUANX_NAME_SYSTEM           = 0x7A,

  TX_EXTRA_MYSTERIOUS_MINERGATE_TAG       = 0xDE;

constexpr char
  TX_EXTRA_NONCE_PAYMENT_ID               = 0x00,
  TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID     = 0x01;

}

namespace lns
{
enum struct extra_field : uint8_t
{
  none            = 0,
  owner           = 1 << 0,
  backup_owner    = 1 << 1,
  signature       = 1 << 2,
  encrypted_value = 1 << 3,

  // Bit Masks
  updatable_fields = (extra_field::owner | extra_field::backup_owner | extra_field::encrypted_value),
  buy_no_backup    = (extra_field::owner | extra_field::encrypted_value),
  buy              = (extra_field::buy_no_backup | extra_field::backup_owner),
  all              = (extra_field::updatable_fields | extra_field::signature),
};

constexpr inline extra_field operator|(extra_field a, extra_field b) { return static_cast<extra_field>(static_cast<uint8_t>(a) | static_cast<uint8_t>(b)); }
constexpr inline extra_field operator&(extra_field a, extra_field b) { return static_cast<extra_field>(static_cast<uint8_t>(a) & static_cast<uint8_t>(b)); }
constexpr inline extra_field& operator|=(extra_field& a, extra_field b) { return a = a | b; }
constexpr inline extra_field& operator&=(extra_field& a, extra_field b) { return a = a & b; }

enum struct  generic_owner_sig_type : uint8_t { monero, ed25519, _count };
struct alignas(size_t) generic_owner
{
  union {
    crypto::ed25519_public_key ed25519;
    struct
    {
      cryptonote::account_public_address address;
      bool is_subaddress;
      char padding01_[7];
    } wallet;
  };

  generic_owner_sig_type type;
  char                   padding02_[7];

  std::string to_string(cryptonote::network_type nettype) const;
  explicit operator bool() const { return (type == generic_owner_sig_type::monero) ? wallet.address != cryptonote::null_address : ed25519; }
  bool operator==(generic_owner const &other) const;

  BEGIN_SERIALIZE()
    ENUM_FIELD(type, type < generic_owner_sig_type::_count)
    if (type == generic_owner_sig_type::monero)
    {
      FIELD(wallet.address);
      FIELD(wallet.is_subaddress);
    }
    else
    {
      FIELD(ed25519);
    }
  END_SERIALIZE()
};
static_assert(sizeof(generic_owner) == 80, "Unexpected padding, we store binary blobs into the LNS DB");

struct generic_signature
{
  generic_owner_sig_type type;
  union
  {
    crypto::ed25519_signature ed25519;
    crypto::signature         monero;
    unsigned char             data[sizeof(crypto::ed25519_signature)];
  };
  static constexpr generic_signature null() { return {}; }
  explicit operator bool() const { return memcmp(data, null().data, sizeof(data)); }
  bool operator==(generic_signature const &other) const { return other.type == type && memcmp(data, other.data, sizeof(data)) == 0; }

  BEGIN_SERIALIZE()
    ENUM_FIELD(type, type < generic_owner_sig_type::_count)
    FIELD(ed25519);
  END_SERIALIZE()
};
static_assert(sizeof(crypto::ed25519_signature) == sizeof(crypto::signature), "LNS allows storing either ed25519 or monero style signatures, we store all signatures into crypto::signature in LNS");
inline std::ostream &operator<<(std::ostream &o, const generic_signature &v) { epee::to_hex::formatted(o, epee::as_byte_span(v.data)); return o; }
}

namespace std {
  static_assert(sizeof(lns::generic_owner) >= sizeof(std::size_t) && alignof(lns::generic_owner) >= alignof(std::size_t),
                "Size and alignment of hash must be at least that of size_t");
  template <> struct hash<lns::generic_owner> {
    std::size_t operator()(const lns::generic_owner &v) const { return reinterpret_cast<const std::size_t &>(v); }
  };
}

namespace gnodes {
  enum class new_state : uint16_t
  {
    deregister,
    decommission,
    recommission,
    ip_change_penalty,
    _count,
  };
}

namespace cryptonote
{
  struct tx_extra_padding
  {
    size_t size;
  };

  template <class Archive>
  void serialize_value(Archive& ar, tx_extra_padding& pad)
  {
    size_t remaining;
    if constexpr (Archive::is_deserializer)
      remaining = ar.remaining_bytes();
    else if (pad.size <= 1)
      return;
    else
      remaining = pad.size - 1; // - 1 here (and just below) because we consider the 0x00 variant tag part of the padding

    if (remaining > TX_EXTRA_PADDING_MAX_COUNT - 1) // - 1 as above.
      throw std::invalid_argument{"tx_extra_padding size is larger than maximum allowed"};

    char buf[TX_EXTRA_PADDING_MAX_COUNT - 1] = {};
    ar.serialize_blob(buf, remaining);

    if (Archive::is_deserializer)
    {
      if (std::string_view{buf, remaining}.find_first_not_of('\0') != std::string::npos)
        throw std::invalid_argument{"Invalid non-0 padding byte"};
      pad.size = remaining + 1;
    }
  }

  struct tx_extra_pub_key
  {
    crypto::public_key pub_key;

    BEGIN_SERIALIZE()
      FIELD(pub_key)
    END_SERIALIZE()
  };

  struct tx_extra_nonce
  {
    std::string nonce;

    BEGIN_SERIALIZE()
      FIELD(nonce)
      if(TX_EXTRA_NONCE_MAX_COUNT < nonce.size())
        throw std::invalid_argument{"invalid extra nonce: too long"};
    END_SERIALIZE()
  };

  struct tx_extra_merge_mining_tag
  {
    size_t depth;
    crypto::hash merkle_root;
  };

  template <class Archive>
  void inner_serializer(Archive& ar, tx_extra_merge_mining_tag& mm)
  {
    field_varint(ar, "depth", mm.depth);
    field(ar, "merkle_root", mm.merkle_root);
  }

  // load
  template <class Archive, std::enable_if_t<Archive::is_deserializer, int> = 0>
  void serialize_value(Archive& ar, tx_extra_merge_mining_tag& mm)
  {
    // MM tag gets binary-serialized into a string, and then that string gets serialized (as a
    // string).  This is very strange.
    std::string field;
    value(ar, field);

    serialization::binary_string_unarchiver inner_ar{field};
    inner_serializer(inner_ar, mm);
  }

  // store
  template <class Archive, std::enable_if_t<Archive::is_serializer, int> = 0>
  void serialize_value(Archive& ar, tx_extra_merge_mining_tag& mm)
  {
    // As above: first we binary-serialize into a string, then we serialize the string.
    serialization::binary_string_archiver inner_ar;
    inner_serializer(inner_ar, mm);

    std::string field = inner_ar.str();
    value(ar, field);
  }

  // per-output additional tx pubkey for multi-destination transfers involving at least one subaddress
  struct tx_extra_additional_pub_keys
  {
    std::vector<crypto::public_key> data;

    BEGIN_SERIALIZE()
      FIELD(data)
    END_SERIALIZE()
  };

  struct tx_extra_mysterious_minergate
  {
    std::string data;

    BEGIN_SERIALIZE()
      FIELD(data)
    END_SERIALIZE()
  };

  struct tx_extra_gnode_winner
  {
    crypto::public_key m_gnode_key;

    BEGIN_SERIALIZE()
      FIELD(m_gnode_key)
    END_SERIALIZE()
  };

  struct tx_extra_gnode_pubkey
  {
    crypto::public_key m_gnode_key;

    BEGIN_SERIALIZE()
      FIELD(m_gnode_key)
    END_SERIALIZE()
  };


  struct tx_extra_gnode_register
  {
    std::vector<crypto::public_key> m_public_spend_keys;
    std::vector<crypto::public_key> m_public_view_keys;
    uint64_t m_portions_for_operator;
    std::vector<uint64_t> m_portions;
    uint64_t m_expiration_timestamp;
    crypto::signature m_gnode_signature;

    BEGIN_SERIALIZE()
      FIELD(m_public_spend_keys)
      FIELD(m_public_view_keys)
      FIELD(m_portions_for_operator)
      FIELD(m_portions)
      FIELD(m_expiration_timestamp)
      FIELD(m_gnode_signature)
    END_SERIALIZE()
  };

  struct tx_extra_gnode_contributor
  {
    crypto::public_key m_spend_public_key;
    crypto::public_key m_view_public_key;

    BEGIN_SERIALIZE()
      FIELD(m_spend_public_key)
      FIELD(m_view_public_key)
    END_SERIALIZE()
  };

  struct tx_extra_gnode_state_change
  {
    struct vote
    {
      vote() = default;
      vote(crypto::signature const &signature, uint32_t validator_index): signature(signature), validator_index(validator_index) { }
      crypto::signature signature;
      uint32_t          validator_index;

      BEGIN_SERIALIZE()
        VARINT_FIELD(validator_index);
        FIELD(signature);
      END_SERIALIZE()
    };

    gnodes::new_state state;
    uint64_t                 block_height;
    uint32_t                 gnode_index;
    std::vector<vote>        votes;

    tx_extra_gnode_state_change() = default;

    template <typename... VotesArgs>
    tx_extra_gnode_state_change(gnodes::new_state state, uint64_t block_height, uint32_t gnode_index, VotesArgs &&...votes)
        : state{state}, block_height{block_height}, gnode_index{gnode_index}, votes{std::forward<VotesArgs>(votes)...} {}

    // Compares equal if this represents a state change of the same SN (does *not* require equality of stored votes)
    bool operator==(const tx_extra_gnode_state_change &sc) const {
      return state == sc.state && block_height == sc.block_height && gnode_index == sc.gnode_index;
    }

    BEGIN_SERIALIZE()
      ENUM_FIELD(state, state < gnodes::new_state::_count);
      VARINT_FIELD(block_height);
      VARINT_FIELD(gnode_index);
      FIELD(votes);
    END_SERIALIZE()
  };

  // Pre-Heimdall service node deregistration data; it doesn't carry the state change (it is only
  // used for deregistrations), and is stored slightly less efficiently in the tx extra data.
  struct tx_extra_gnode_deregister_old
  {
#pragma pack(push, 4)
    struct vote { // Not simply using state_change::vote because this gets blob serialized for v11 backwards compat
      vote() = default;
      vote(const tx_extra_gnode_state_change::vote &v) : signature{v.signature}, validator_index{v.validator_index} {}
      crypto::signature signature;
      uint32_t          validator_index;

      operator tx_extra_gnode_state_change::vote() const { return {signature, validator_index}; }
    };
#pragma pack(pop)
    static_assert(sizeof(vote) == sizeof(crypto::signature) + sizeof(uint32_t), "deregister_old tx extra vote size is not packed");

    uint64_t          block_height;
    uint32_t          gnode_index;
    std::vector<vote> votes;

    tx_extra_gnode_deregister_old() = default;
    tx_extra_gnode_deregister_old(const tx_extra_gnode_state_change &state_change)
      : block_height{state_change.block_height},
        gnode_index{state_change.gnode_index},
        votes{state_change.votes.begin(), state_change.votes.end()}
    {
      assert(state_change.state == gnodes::new_state::deregister);
    }

    BEGIN_SERIALIZE()
      FIELD(block_height)
      FIELD(gnode_index)
      FIELD(votes)
    END_SERIALIZE()
  };

  struct tx_extra_tx_secret_key
  {
    crypto::secret_key key;

    BEGIN_SERIALIZE()
      FIELD(key)
    END_SERIALIZE()
  };

  struct tx_extra_tx_key_image_proofs
  {
    struct proof
    {
      crypto::key_image key_image;
      crypto::signature signature;
    };
    static_assert(sizeof(proof) == sizeof(crypto::key_image) + sizeof(crypto::signature), "tx_extra key image proof data structure is not packed");

    std::vector<proof> proofs;

    BEGIN_SERIALIZE()
      FIELD(proofs)
    END_SERIALIZE()
  };

  struct tx_extra_tx_key_image_unlock
  {
    crypto::key_image key_image;
    crypto::signature signature;
    uint32_t          nonce;

    // Compares equal if this represents the same key image unlock (but does *not* require equality of signature/nonce)
    bool operator==(const tx_extra_tx_key_image_unlock &other) const { return key_image == other.key_image; }

    BEGIN_SERIALIZE()
      FIELD(key_image)
      FIELD(signature)
      FIELD(nonce)
    END_SERIALIZE()
  };

  struct tx_extra_burn
  {
    uint64_t amount;

    BEGIN_SERIALIZE()
      FIELD(amount)
    END_SERIALIZE()
  };

  struct tx_extra_gyuanx_name_system
  {
    uint8_t                 version = 0;
    lns::mapping_type       type;
    crypto::hash            name_hash;
    crypto::hash            prev_txid = crypto::null_hash;  // previous txid that purchased the mapping
    lns::extra_field        fields;
    lns::generic_owner      owner        = {};
    lns::generic_owner      backup_owner = {};
    lns::generic_signature  signature    = {};
    std::string             encrypted_value; // binary format of the name->value mapping

    bool field_is_set (lns::extra_field bit) const { return (fields & bit) == bit; }
    bool field_any_set(lns::extra_field bit) const { return (fields & bit) != lns::extra_field::none; }

    // True if this is updating some LNS info: has a signature and 1 or more updating field
    bool is_updating() const { return field_is_set(lns::extra_field::signature) && field_any_set(lns::extra_field::updatable_fields); }
    // True if this is buying a new LNS record
    bool is_buying()   const { return (fields == lns::extra_field::buy || fields == lns::extra_field::buy_no_backup); }
    // True if this is renewing an existing LNS: has no fields at all, is a renewal registration (i.e. gyuanxnet),
    // and has a non-null txid set (which should point to the most recent registration or update).
    bool is_renewing() const { return fields == lns::extra_field::none && prev_txid && is_gyuanxnet_type(type); }

    static tx_extra_gyuanx_name_system make_buy(lns::generic_owner const &owner, lns::generic_owner const *backup_owner, lns::mapping_type type, crypto::hash const &name_hash, std::string const &encrypted_value, crypto::hash const &prev_txid)
    {
      tx_extra_gyuanx_name_system result = {};
      result.fields                    = lns::extra_field::buy;
      result.owner                     = owner;

      if (backup_owner)
        result.backup_owner = *backup_owner;
      else
        result.fields = lns::extra_field::buy_no_backup;

      result.type            = type;
      result.name_hash       = name_hash;
      result.encrypted_value = encrypted_value;
      result.prev_txid       = prev_txid;
      return result;
    }

    static tx_extra_gyuanx_name_system make_renew(lns::mapping_type type, crypto::hash const &name_hash, crypto::hash const &prev_txid)
    {
      assert(is_gyuanxnet_type(type) && prev_txid);

      tx_extra_gyuanx_name_system result{};
      result.fields = lns::extra_field::none;
      result.type = type;
      result.name_hash = name_hash;
      result.prev_txid = prev_txid;
      return result;
    }

    static tx_extra_gyuanx_name_system make_update(lns::generic_signature const &signature,
                                                 lns::mapping_type type,
                                                 crypto::hash const &name_hash,
                                                 std::string_view encrypted_value,
                                                 lns::generic_owner const *owner,
                                                 lns::generic_owner const *backup_owner,
                                                 crypto::hash const &prev_txid)
    {
      tx_extra_gyuanx_name_system result = {};
      result.signature                 = signature;
      result.type                      = type;
      result.name_hash                 = name_hash;
      result.fields |= lns::extra_field::signature;

      if (encrypted_value.size())
      {
        result.fields |= lns::extra_field::encrypted_value;
        result.encrypted_value = std::string(reinterpret_cast<char const *>(encrypted_value.data()), encrypted_value.size());
      }

      if (owner)
      {
        result.fields |= lns::extra_field::owner;
        result.owner = *owner;
      }

      if (backup_owner)
      {
        result.fields |= lns::extra_field::backup_owner;
        result.backup_owner = *backup_owner;
      }

      result.prev_txid = prev_txid;
      return result;
    }

    BEGIN_SERIALIZE()
      FIELD(version)
      ENUM_FIELD(type, type < lns::mapping_type::_count)
      FIELD(name_hash)
      FIELD(prev_txid)
      ENUM_FIELD(fields, fields <= lns::extra_field::all)
      if (field_is_set(lns::extra_field::owner)) FIELD(owner);
      if (field_is_set(lns::extra_field::backup_owner)) FIELD(backup_owner);
      if (field_is_set(lns::extra_field::signature)) FIELD(signature);
      if (field_is_set(lns::extra_field::encrypted_value)) FIELD(encrypted_value);
    END_SERIALIZE()
  };

  // tx_extra_field format, except tx_extra_padding and tx_extra_pub_key:
  //   varint tag;
  //   varint size;
  //   varint data[];
  //
  // Note that the order of fields here also determines the tx extra sort order.  You should not
  // change the relative orders of existing tags, but new tags can be added wherever seems
  // appropriate.
  using tx_extra_field = std::variant<
      tx_extra_pub_key,
      tx_extra_gnode_winner,
      tx_extra_additional_pub_keys,
      tx_extra_nonce,
      tx_extra_gnode_register,
      tx_extra_gnode_deregister_old,
      tx_extra_gnode_state_change,
      tx_extra_gnode_contributor,
      tx_extra_gnode_pubkey,
      tx_extra_tx_secret_key,
      tx_extra_gyuanx_name_system,
      tx_extra_tx_key_image_proofs,
      tx_extra_tx_key_image_unlock,
      tx_extra_burn,
      tx_extra_merge_mining_tag,
      tx_extra_mysterious_minergate,
      tx_extra_padding
      >;
}

BLOB_SERIALIZER(cryptonote::tx_extra_gnode_deregister_old::vote);
BLOB_SERIALIZER(cryptonote::tx_extra_tx_key_image_proofs::proof);

BINARY_VARIANT_TAG(cryptonote::tx_extra_padding,                     cryptonote::TX_EXTRA_TAG_PADDING);
BINARY_VARIANT_TAG(cryptonote::tx_extra_pub_key,                     cryptonote::TX_EXTRA_TAG_PUBKEY);
BINARY_VARIANT_TAG(cryptonote::tx_extra_nonce,                       cryptonote::TX_EXTRA_NONCE);
BINARY_VARIANT_TAG(cryptonote::tx_extra_merge_mining_tag,            cryptonote::TX_EXTRA_MERGE_MINING_TAG);
BINARY_VARIANT_TAG(cryptonote::tx_extra_additional_pub_keys,         cryptonote::TX_EXTRA_TAG_ADDITIONAL_PUBKEYS);
BINARY_VARIANT_TAG(cryptonote::tx_extra_mysterious_minergate,        cryptonote::TX_EXTRA_MYSTERIOUS_MINERGATE_TAG);
BINARY_VARIANT_TAG(cryptonote::tx_extra_gnode_register,       cryptonote::TX_EXTRA_TAG_SERVICE_NODE_REGISTER);
BINARY_VARIANT_TAG(cryptonote::tx_extra_gnode_state_change,   cryptonote::TX_EXTRA_TAG_SERVICE_NODE_STATE_CHANGE);
BINARY_VARIANT_TAG(cryptonote::tx_extra_gnode_deregister_old, cryptonote::TX_EXTRA_TAG_SERVICE_NODE_DEREG_OLD);
BINARY_VARIANT_TAG(cryptonote::tx_extra_gnode_contributor,    cryptonote::TX_EXTRA_TAG_SERVICE_NODE_CONTRIBUTOR);
BINARY_VARIANT_TAG(cryptonote::tx_extra_gnode_winner,         cryptonote::TX_EXTRA_TAG_SERVICE_NODE_WINNER);
BINARY_VARIANT_TAG(cryptonote::tx_extra_gnode_pubkey,         cryptonote::TX_EXTRA_TAG_SERVICE_NODE_PUBKEY);
BINARY_VARIANT_TAG(cryptonote::tx_extra_tx_secret_key,               cryptonote::TX_EXTRA_TAG_TX_SECRET_KEY);
BINARY_VARIANT_TAG(cryptonote::tx_extra_tx_key_image_proofs,         cryptonote::TX_EXTRA_TAG_TX_KEY_IMAGE_PROOFS);
BINARY_VARIANT_TAG(cryptonote::tx_extra_tx_key_image_unlock,         cryptonote::TX_EXTRA_TAG_TX_KEY_IMAGE_UNLOCK);
BINARY_VARIANT_TAG(cryptonote::tx_extra_burn,                        cryptonote::TX_EXTRA_TAG_BURN);
BINARY_VARIANT_TAG(cryptonote::tx_extra_gyuanx_name_system,            cryptonote::TX_EXTRA_TAG_GYUANX_NAME_SYSTEM);
