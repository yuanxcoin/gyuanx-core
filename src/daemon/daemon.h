// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
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
#include <boost/program_options.hpp>

#include "blocks/blocks.h"
#include "rpc/core_rpc_server.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "misc_log_ex.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize
{
struct rpc_server
{
  rpc_server(boost::program_options::variables_map const &vm,
             cryptonote::core &core,
             nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>> &p2p,
             const bool restricted,
             const std::string &port,
             const std::string &description);
  void run();
  void stop();
  ~rpc_server();

  cryptonote::core_rpc_server m_server;
  std::string m_description;
};

struct daemon
{
  static void init_options(boost::program_options::options_description & option_spec);

  daemon(boost::program_options::variables_map const &vm, uint16_t public_rpc_port = 0);
  ~daemon();
  bool run(bool interactive = false);
  void stop_p2p();
  void stop();

  boost::program_options::variables_map vm;
  uint16_t    public_rpc_port;
  std::string zmq_rpc_bind_address;
  std::string zmq_rpc_bind_port;

  cryptonote::core core;
  cryptonote::t_cryptonote_protocol_handler<cryptonote::core> protocol;
  nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>> p2p;
  std::vector<std::unique_ptr<rpc_server>> rpc_servers;
};
} // namespace daemonize
