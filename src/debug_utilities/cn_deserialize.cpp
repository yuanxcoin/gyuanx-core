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

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/blockchain.h"
#include "common/command_line.h"
#include "cryptonote_config.h"
#include "common/hex.h"
#include "version.h"
#include <gyuanxmq/hex.h>

#undef GYUANX_DEFAULT_LOG_CATEGORY
#define GYUANX_DEFAULT_LOG_CATEGORY "debugtools.deserialize"

namespace po = boost::program_options;

using namespace cryptonote;

static std::string extra_nonce_to_string(const cryptonote::tx_extra_nonce &extra_nonce)
{
  if (extra_nonce.nonce.size() == 9 && extra_nonce.nonce[0] == TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID)
    return "encrypted payment ID: " + gyuanxmq::to_hex(extra_nonce.nonce.begin() + 1, extra_nonce.nonce.end());
  if (extra_nonce.nonce.size() == 33 && extra_nonce.nonce[0] == TX_EXTRA_NONCE_PAYMENT_ID)
    return "plaintext payment ID: " + gyuanxmq::to_hex(extra_nonce.nonce.begin() + 1, extra_nonce.nonce.end());
  return gyuanxmq::to_hex(extra_nonce.nonce);
}

struct extra_printer {
  void operator()(const tx_extra_padding& x) { std::cout << "padding: " << x.size << " bytes"; }
  void operator()(const tx_extra_pub_key& x) { std::cout << "pub key: " << x.pub_key; }
  void operator()(const tx_extra_nonce& x) { std::cout << "nonce: " << extra_nonce_to_string(x); }
  void operator()(const tx_extra_merge_mining_tag& x) { std::cout << "merge mining tag: depth " << x.depth << ", merkle root " << x.merkle_root; }
  void operator()(const tx_extra_additional_pub_keys& x) {
    std::cout << "additional tx pubkeys: ";
    bool first = true;
    for (auto& pk : x.data) {
      if (first) first = false;
      else std::cout << ", ";
      std::cout << pk;
    }
  }
  void operator()(const tx_extra_mysterious_minergate& x) { std::cout << "minergate custom: " << gyuanxmq::to_hex(x.data); }
  void operator()(const tx_extra_gnode_winner& x) { std::cout << "SN reward winner: " << x.m_gnode_key; }
  void operator()(const tx_extra_gnode_register& x) { std::cout << "SN registration data"; } // TODO: could parse this further
  void operator()(const tx_extra_gnode_pubkey& x) { std::cout << "SN pubkey: " << x.m_gnode_key; }
  void operator()(const tx_extra_gnode_contributor& x) { std::cout << "SN contribution"; } // Can't actually print the address without knowing the network type
  void operator()(const tx_extra_gnode_deregister_old& x) { std::cout << "SN deregistration (pre-HF12)"; }
  void operator()(const tx_extra_tx_secret_key& x) { std::cout << "TX secret key: " << tools::type_to_hex(x.key); }
  void operator()(const tx_extra_tx_key_image_proofs& x) { std::cout << "TX key image proofs (" << x.proofs.size() << ")"; }
  void operator()(const tx_extra_tx_key_image_unlock& x) { std::cout << "TX key image unlock: " << x.key_image; }
  void operator()(const tx_extra_burn& x) { std::cout << "Transaction burned fee/payment: " << print_money(x.amount); }
  void operator()(const tx_extra_gyuanx_name_system& x) {
    std::cout << "LNS " << (x.is_buying() ? "registration" : x.is_updating() ? "update" : "(unknown)");
    switch (x.type)
    {
      case lns::mapping_type::gyuanxnet: std::cout << " - Gyuanxnet (1y)"; break;
      case lns::mapping_type::gyuanxnet_2years: std::cout << " - Gyuanxnet (2y)"; break;
      case lns::mapping_type::gyuanxnet_5years: std::cout << " - Gyuanxnet (5y)"; break;
      case lns::mapping_type::gyuanxnet_10years: std::cout << " - Gyuanxnet (10y)"; break;
      case lns::mapping_type::session: std::cout << " - Session address"; break;
      case lns::mapping_type::wallet: std::cout << " - Wallet address"; break;
      case lns::mapping_type::update_record_internal:
      case lns::mapping_type::_count:
          break;
    }
  }
  void operator()(const tx_extra_gnode_state_change& x) {
    std::cout << "SN state change: ";
    switch (x.state)
    {
      case gnodes::new_state::decommission: std::cout << "decommission"; break;
      case gnodes::new_state::recommission: std::cout << "recommission"; break;
      case gnodes::new_state::deregister: std::cout << "deregister"; break;
      case gnodes::new_state::ip_change_penalty: std::cout << "ip change penalty"; break;
      case gnodes::new_state::_count: std::cout << "(unknown)"; break;
    }
    std::cout << " for block height " << x.block_height << ", SN index " << x.gnode_index;
  }
  template <typename T> void operator()(const T&) { std::cout << "unknown"; }
};


static void print_extra_fields(const std::vector<cryptonote::tx_extra_field> &fields)
{
  std::cout << "tx_extra has " << fields.size() << " field(s)\n";
  for (size_t n = 0; n < fields.size(); ++n)
  {
    std::cout << "- " << n << ": ";
    var::visit(extra_printer{}, fields[n]);
    std::cout << "\n";
  }
}

int main(int argc, char* argv[])
{
  uint32_t log_level = 0;
  std::string input;

  tools::on_startup();

  po::options_description desc_cmd_only("Command line options");
  po::options_description desc_cmd_sett("Command line options and settings options");
  const command_line::arg_descriptor<uint32_t> arg_log_level = {"log-level", "", log_level};
  const command_line::arg_descriptor<std::string> arg_input  = {
      "input", "Specify a wallet address or hex string of a Cryptonote type for decoding, supporting\n"
               " - TX Extra\n"
               " - Block\n"
               " - Transaction\n"
              ,""};

  command_line::add_arg(desc_cmd_sett, arg_log_level);
  command_line::add_arg(desc_cmd_sett, arg_input);

  command_line::add_arg(desc_cmd_only, command_line::arg_help);

  po::options_description desc_options("Allowed options");
  desc_options.add(desc_cmd_only).add(desc_cmd_sett);

  po::variables_map vm;
  bool r = command_line::handle_error_helper(desc_options, [&]()
  {
    po::store(po::parse_command_line(argc, argv, desc_options), vm);
    po::notify(vm);
    return true;
  });
  if (! r)
    return 1;

  if (command_line::get_arg(vm, command_line::arg_help))
  {
    std::cout << "Gyuanx '" << GYUANX_RELEASE_NAME << "' (v" << GYUANX_VERSION_FULL << ")\n\n";
    std::cout << desc_options << std::endl;
    return 1;
  }

  log_level    = command_line::get_arg(vm, arg_log_level);
  input        = command_line::get_arg(vm, arg_input);
  if (input.empty())
  {
    std::cerr << "Usage: --input <hex|wallet address>" << std::endl;
    return 1;
  }

  mlog_configure("", true);

  cryptonote::blobdata blob;
  if (epee::string_tools::parse_hexstr_to_binbuff(input, blob))
  {
    bool full;
    cryptonote::block block;
    cryptonote::transaction tx;
    std::vector<cryptonote::tx_extra_field> fields;
    if (cryptonote::parse_and_validate_block_from_blob(blob, block))
    {
      std::cout << "Parsed block:" << std::endl;
      std::cout << cryptonote::obj_to_json_str(block) << std::endl;
    }
    else if (cryptonote::parse_and_validate_tx_from_blob(blob, tx) || cryptonote::parse_and_validate_tx_base_from_blob(blob, tx))
    {
      if (tx.pruned)
        std::cout << "Parsed pruned transaction:" << std::endl;
      else
        std::cout << "Parsed transaction:" << std::endl;
      std::cout << cryptonote::obj_to_json_str(tx) << std::endl;

      bool parsed = cryptonote::parse_tx_extra(tx.extra, fields);
      if (!parsed)
        std::cout << "Failed to parse tx_extra" << std::endl;

      if (!fields.empty())
      {
        print_extra_fields(fields);
      }
      else
      {
        std::cout << "No fields were found in tx_extra" << std::endl;
      }
    }
    else if (((full = cryptonote::parse_tx_extra(std::vector<uint8_t>(blob.begin(), blob.end()), fields)) || true) && !fields.empty())
    {
      std::cout << "Parsed" << (full ? "" : " partial") << " tx_extra:" << std::endl;
      print_extra_fields(fields);
    }
    else
    {
      std::cerr << "Not a recognized CN type" << std::endl;
      return 1;
    }
  }
  else
  {
    bool addr_decoded = false;
    for (uint8_t nettype = MAINNET; nettype < DEVNET + 1;  nettype++)
    {
      cryptonote::address_parse_info addr_info = {};
      if (cryptonote::get_account_address_from_str(addr_info, static_cast<cryptonote::network_type>(nettype), input))
      {
        addr_decoded = true;
        cryptonote::account_public_address const &address = addr_info.address;
        std::cout << "Network Type: " << cryptonote::network_type_str(static_cast<cryptonote::network_type>(nettype)) << "\n";
        std::cout << "Address: " << input << "\n";
        std::cout << "Subaddress: " << (addr_info.is_subaddress ? "Yes" : "No") << "\n";
        std::cout << "Payment ID: " << (addr_info.has_payment_id ? tools::type_to_hex(addr_info.payment_id) : "(none)") << "\n";
        std::cout << "Spend Public Key: " << address.m_spend_public_key << "\n";
        std::cout << "View Public Key: " << address.m_view_public_key << "\n";
      }
    }

    if (!addr_decoded)
    {
      std::cerr << "Not a recognized CN type" << std::endl;
      return 1;
    }
  }



  return 0;
}
