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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <memory>
#include <stdexcept>
#include <boost/algorithm/string/split.hpp>
#include "misc_log_ex.h"
#include "daemon/daemon.h"
#include "rpc/daemon_handler.h"
#include "rpc/zmq_server.h"
#include "cryptonote_protocol/quorumnet.h"

#include "common/password.h"
#include "common/util.h"
#include "daemon/command_server.h"
#include "daemon/command_line_args.h"
#include "net/net_ssl.h"
#include "version.h"

using namespace epee;

#include <functional>

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

rpc_server::rpc_server(boost::program_options::variables_map const &vm,
                       cryptonote::core &core,
                       nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>> &p2p,
                       const bool restricted,
                       const std::string &port,
                       const std::string &description)
: m_server{core, p2p}
, m_description{description}
{
  MGINFO("Initializing " << m_description << " RPC server...");
  if (!m_server.init(vm, restricted, port))
  {
    throw std::runtime_error("Failed to initialize " + m_description + " RPC server.");
  }
  MGINFO(m_description << " RPC server initialized OK on port: " << m_server.get_binded_port());
}

void rpc_server::run()
{
  MGINFO("Starting " << m_description << " RPC server...");
  if (!m_server.run(m_server.m_max_long_poll_connections + cryptonote::core_rpc_server::DEFAULT_RPC_THREADS,
                    false /*wait - for all threads in the pool to exit when terminating*/))
  {
    throw std::runtime_error("Failed to start " + m_description + " RPC server.");
  }
  MGINFO(m_description << " RPC server started ok");
}

void rpc_server::stop()
{
  MGINFO("Stopping " << m_description << " RPC server...");
  m_server.send_stop_signal();
  m_server.timed_wait_server_stop(5000);
}

rpc_server::~rpc_server()
{
  MGINFO("Deinitializing " << m_description << " RPC server...");
  try
  {
    m_server.deinit();
  }
  catch (...)
  {
    MERROR("Failed to deinitialize " << m_description << " RPC server...");
  }
}

void daemon::init_options(boost::program_options::options_description & option_spec)
{
  cryptonote::core::init_options(option_spec);
  nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>>::init_options(option_spec);
  cryptonote::core_rpc_server::init_options(option_spec);
}

daemon::daemon(boost::program_options::variables_map const &vm, uint16_t public_rpc_port)
: vm(vm)
, public_rpc_port(public_rpc_port)
, zmq_rpc_bind_port(command_line::get_arg(vm, daemon_args::arg_zmq_rpc_bind_port))
, zmq_rpc_bind_address(command_line::get_arg(vm, daemon_args::arg_zmq_rpc_bind_ip))
, core(nullptr)
, protocol(core, nullptr /*p_net_layout*/, command_line::get_arg(vm, cryptonote::arg_offline))
, p2p(protocol)
{
  MGINFO("Initializing cryptonote protocol...");
  if (!protocol.init(vm))
  {
    throw std::runtime_error("Failed to initialize cryptonote protocol.");
  }
  MGINFO("Cryptonote protocol initialized OK");

  MGINFO("Initializing p2p server...");
  if (!p2p.init(vm))
  {
    throw std::runtime_error("Failed to initialize p2p server.");
  }
  MGINFO("p2p server initialized OK");

  // Handle circular dependencies
  protocol.set_p2p_endpoint(&p2p);
  core.set_cryptonote_protocol(&protocol);
  quorumnet::init_core_callbacks();

  const auto restricted = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_restricted_rpc);
  const auto main_rpc_port = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port);
  rpc_servers.emplace_back(new rpc_server{vm, core, p2p, restricted, main_rpc_port, "core"});

  auto restricted_rpc_port_arg = cryptonote::core_rpc_server::arg_rpc_restricted_bind_port;
  if(!command_line::is_arg_defaulted(vm, restricted_rpc_port_arg))
  {
    auto restricted_rpc_port = command_line::get_arg(vm, restricted_rpc_port_arg);
    rpc_servers.emplace_back(new rpc_server{vm, core, p2p, true /*restricted*/, restricted_rpc_port, "restricted"});
  }
}

daemon::~daemon()
{
  MGINFO("Deinitializing core...");
  try
  {
    core.deinit();
    core.set_cryptonote_protocol(nullptr);
  }
  catch (...)
  {
    MERROR("Failed to deinitialize core...");
  }

  MGINFO("Stopping cryptonote protocol...");
  try
  {
    protocol.deinit();
    protocol.set_p2p_endpoint(nullptr);
    MGINFO("Cryptonote protocol stopped successfully");
  }
  catch (...)
  {
    LOG_ERROR("Failed to stop cryptonote protocol!");
  }

  MGINFO("Deinitializing p2p...");
  try
  {
    p2p.deinit();
  }
  catch (...)
  {
    MERROR("Failed to deinitialize p2p...");
  }
}

bool daemon::run(bool interactive)
{
  std::atomic<bool> stop(false), shutdown(false);
  boost::thread stop_thread = boost::thread([&stop, &shutdown, this] {
    while (!stop)
      epee::misc_utils::sleep_no_w(100);
    if (shutdown)
      this->stop_p2p();
  });

  LOKI_DEFER
  {
    stop = true;
    stop_thread.join();
  };

  tools::signal_handler::install([&stop, &shutdown](int) { stop = shutdown = true; });

  try
  {
    // NOTE: Initialize Core
    {
      MGINFO("Initializing core...");
#if defined(PER_BLOCK_CHECKPOINT)
      const cryptonote::GetCheckpointsCallback& get_checkpoints = blocks::GetCheckpointsData;
#else
      const cryptonote::GetCheckpointsCallback& get_checkpoints = nullptr;
#endif
      if (!core.init(vm, nullptr, get_checkpoints))
      {
        return false;
      }
      MGINFO("Core initialized OK");
    }

    for(auto& rpc: rpc_servers)
      rpc->run();

    std::unique_ptr<daemonize::t_command_server> rpc_commands;
    if (interactive && rpc_servers.size())
    {
      // The first three variables are not used when the fourth is false
      rpc_commands.reset(new daemonize::t_command_server(0, 0, boost::none, epee::net_utils::ssl_support_t::e_ssl_support_disabled, false, &rpc_servers.front()->m_server));
      rpc_commands->start_handling(std::bind(&daemonize::daemon::stop_p2p, this));
    }

    cryptonote::rpc::DaemonHandler rpc_daemon_handler(core, p2p);
    cryptonote::rpc::ZmqServer zmq_server(rpc_daemon_handler);

    if (!zmq_server.addTCPSocket(zmq_rpc_bind_address, zmq_rpc_bind_port))
    {
      LOG_ERROR(std::string("Failed to add TCP Socket (") + zmq_rpc_bind_address
          + ":" + zmq_rpc_bind_port + ") to ZMQ RPC Server");

      if (rpc_commands)
        rpc_commands->stop_handling();

      for(auto& rpc : rpc_servers)
        rpc->stop();

      return false;
    }

    MINFO("Starting ZMQ server...");
    zmq_server.run();

    MINFO(std::string("ZMQ server started at ") + zmq_rpc_bind_address
          + ":" + zmq_rpc_bind_port + ".");

    if (public_rpc_port > 0)
    {
      MGINFO("Public RPC port " << public_rpc_port << " will be advertised to other peers over P2P");
      p2p.set_rpc_port(public_rpc_port);
    }

    MGINFO("Starting p2p net loop...");
    p2p.run(); // blocks until p2p goes down
    MGINFO("p2p net loop stopped");

    if (rpc_commands)
      rpc_commands->stop_handling();

    zmq_server.stop();

    for(auto& rpc : rpc_servers)
      rpc->stop();
    MGINFO("Node stopped.");
    return true;
  }
  catch (std::exception const & ex)
  {
    MFATAL("Uncaught exception! " << ex.what());
    return false;
  }
  catch (...)
  {
    MFATAL("Uncaught exception!");
    return false;
  }
}

void daemon::stop()
{
  p2p.send_stop_signal();
  for(auto& rpc : rpc_servers)
    rpc->stop();
}

void daemon::stop_p2p()
{
  p2p.send_stop_signal();
}

} // namespace daemonize
