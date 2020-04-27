#include "http_server.h"
#include "rpc/rpc_args.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "daemon.rpc"

namespace cryptonote { namespace rpc {

  using namespace lokimq::literals;

  const command_line::arg_descriptor<std::string, false, true, 2> http_server::arg_rpc_bind_port = {
      "rpc-bind-port"
    , "Port for RPC server"
    , std::to_string(config::RPC_DEFAULT_PORT)
    , {{ &cryptonote::arg_testnet_on, &cryptonote::arg_stagenet_on }}
    , [](std::array<bool, 2> testnet_stagenet, bool defaulted, std::string val)->std::string {
        if (testnet_stagenet[0] && defaulted)
          return std::to_string(config::testnet::RPC_DEFAULT_PORT);
        else if (testnet_stagenet[1] && defaulted)
          return std::to_string(config::stagenet::RPC_DEFAULT_PORT);
        return val;
      }
    };

  const command_line::arg_descriptor<std::string> http_server::arg_rpc_restricted_bind_port = {
      "rpc-restricted-bind-port"
    , "Port for restricted RPC server"
    , ""
    };

  const command_line::arg_descriptor<bool> http_server::arg_restricted_rpc = {
      "restricted-rpc"
    , "Restrict RPC to view only commands and do not return privacy sensitive data in RPC calls"
    , false
    };

  const command_line::arg_descriptor<bool> http_server::arg_public_node = {
      "public-node"
    , "Allow other users to use the node as a remote (restricted RPC mode, view-only commands) and advertise it over P2P"
    , false
    };

  //
  // Loki
  //
  const command_line::arg_descriptor<int> http_server::arg_rpc_long_poll_connections = {
      "rpc-long-poll-connections"
    , "Number of RPC connections allocated for long polling wallet queries to the TX pool"
    , 16
    };

  constexpr int http_server::DEFAULT_RPC_THREADS;

  //-----------------------------------------------------------------------------------
  void http_server::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_rpc_bind_port);
    command_line::add_arg(desc, arg_rpc_restricted_bind_port);
    command_line::add_arg(desc, arg_restricted_rpc);
    command_line::add_arg(desc, arg_public_node);
    command_line::add_arg(desc, arg_rpc_long_poll_connections);
  }

  //------------------------------------------------------------------------------------------------------------------------------
  bool http_server::init(
      const boost::program_options::variables_map& vm
      , const bool restricted
      , const std::string& port
    )
  {
    m_restricted = restricted;
    m_net_server.set_threads_prefix("RPC");
    m_max_long_poll_connections = command_line::get_arg(vm, arg_rpc_long_poll_connections);

    auto rpc_config = cryptonote::rpc_args::process(vm, true);
    if (!rpc_config)
      return false;

    boost::optional<epee::net_utils::http::login> http_login{};

    if (rpc_config->login)
      http_login.emplace(std::move(rpc_config->login->username), std::move(rpc_config->login->password).password());

    auto rng = [](size_t len, uint8_t *ptr){ return crypto::rand(len, ptr); };
    return epee::http_server_impl_base<http_server, connection_context>::init(
      rng, std::move(port), std::move(rpc_config->bind_ip),
      std::move(rpc_config->bind_ipv6_address), std::move(rpc_config->use_ipv6), std::move(rpc_config->require_ipv4),
      std::move(rpc_config->access_control_origins), std::move(http_login), std::move(rpc_config->ssl_options)
    );
  }

  static constexpr http_response_code
    HTTP_OK{200, "OK"_sv},
    HTTP_BAD_REQUEST{400, "Bad Request"_sv},
    HTTP_FORBIDDEN{403, "Forbidden"_sv},
    HTTP_NOT_FOUND{404, "Not Found"_sv},
    HTTP_ERROR{500, "Internal Server Error"_sv};

  bool http_server::handle_http_request(
      const epee::net_utils::http::http_request_info& query_info,
      epee::net_utils::http::http_response_info& response,
      connection_context& context)
  {
    std::chrono::steady_clock::time_point start;
    bool time_logging = LOG_ENABLED(Debug);
    if (time_logging)
      start = std::chrono::steady_clock::now();

    std::pair<int, lokimq::string_view> http_status = HTTP_ERROR;
    std::string exception;
    try {
      http_status = handle_http(query_info, response, context);
    } catch (const std::exception& e) {
      exception = ", request raised an exception: "s + e.what();
    } catch (...) {
      exception = ", request raised an unknown exception";
    }

    response.m_response_code = http_status.first;
    response.m_response_comment = std::string{http_status.second};

    std::string elapsed;
    if (time_logging)
    {
      auto dur = std::chrono::steady_clock::now() - start;
      std::ostringstream el;
      el << ", in ";
      el.precision(3);
      if (dur >= 1s)
        el << std::chrono::duration_cast<std::chrono::milliseconds>(dur).count() / 1000. << 's';
      else if (dur >= 1ms)
        el << std::chrono::duration_cast<std::chrono::microseconds>(dur).count() / 1000. << "ms";
      else if (dur >= 1us)
        el << std::chrono::duration_cast<std::chrono::nanoseconds>(dur).count() / 1000. << "us";
      else
        el << std::chrono::duration_cast<std::chrono::nanoseconds>(dur).count() << "ns";
      elapsed = el.str();
    }

    MLOG(exception.empty() ? el::Level::Info : el::Level::Warning,
        "HTTP [" << context.m_remote_address.host_str() << "] " << query_info.m_http_method_str << " " << query_info.m_URI <<
        " >>> " << http_status.first << " " << http_status.second <<
        exception << elapsed);

    return true;
  }

  static http_response_code json_rpc_error(int code, std::string message, std::string& body)
  {
    epee::json_rpc::error_response rsp;
    rsp.jsonrpc = "2.0";
    rsp.error.code = code;
    rsp.error.message = std::move(message);
    epee::serialization::store_t_to_json(rsp, body);
    return HTTP_OK;
  }

  http_response_code http_server::handle_http(
    const epee::net_utils::http::http_request_info& query_info,
    epee::net_utils::http::http_response_info& response_info,
    connection_context& context)
  {
    auto uri = query_info.m_URI.size() > 0 && query_info.m_URI[0] == '/' ? query_info.m_URI.substr(1) : query_info.m_URI;

    if (uri == "json_rpc")
      return handle_json_rpc_request(query_info, response_info, context);

    auto it = rpc_commands.find(uri);
    if (it == rpc_commands.end())
      return HTTP_NOT_FOUND;

    auto& cmd = *it->second;
    if (m_restricted && !cmd.is_public)
      return HTTP_FORBIDDEN;

    rpc_request request;
    request.context.admin = m_restricted;
    request.body = std::move(query_info.m_body);
    // Really, epee, mime "tipe"?  I suppose that is for when epee analizes the response lacation to
    // see whether the verifivation varialbe failed.
    response_info.m_mime_tipe = cmd.is_binary ? "application/octet-stream" : "application/json";
    response_info.m_header_info.m_content_type = response_info.m_mime_tipe;

    try {
      response_info.m_body = cmd.invoke(std::move(request), m_server);
    } catch (const parse_error& e) {
      // This isn't really WARNable as it's the client fault; log at info level instead.
      MINFO("RPC request for '/" << uri << "' called with invalid/unparseable data: " << e.what());
      return HTTP_BAD_REQUEST;
    } catch (const std::exception& e) {
      MWARNING("RPC request '/" << uri << "' request raised an exception: " << e.what());
      return HTTP_ERROR;
    } catch (...) {
      MWARNING("RPC request '/" << uri << "' request raised an unknown exception");
      return HTTP_ERROR;
    }
  }

  http_response_code http_server::handle_json_rpc_request(
    const epee::net_utils::http::http_request_info& query_info,
    epee::net_utils::http::http_response_info& response_info,
    connection_context& context)
  {
    auto& body = response_info.m_body;

    rpc_request request;
    request.context.admin = m_restricted;
    request.body = jsonrpc_params{};
    auto& epee_stuff = request.body.get_unchecked<jsonrpc_params>();
    auto& ps = epee_stuff.first;
    if(!ps.load_from_json(query_info.m_body))
      return json_rpc_error(-32700, "Parse error", body);

    epee::serialization::storage_entry id{std::string{}};
    ps.get_value("id", id, nullptr);
    std::string method;
    if(!ps.get_value("method", method, nullptr))
      return json_rpc_error(-32600, "Invalid Request", body);

    auto it = rpc_commands.find(method);
    if (it == rpc_commands.end() || it->second->is_binary)
      return json_rpc_error(-32601, "Method not found", body);

    const auto& command = *it->second;
    if (m_restricted && !command.is_public)
      return json_rpc_error(403, "Forbidden; this command is not available over public RPC", body);

    constexpr std::array<lokimq::string_view, 3> json_rpc_ = {
R"({"jsonrpc": "2.0", "id": )"_sv, R"(, "result": )"_sv, R"(
}
)"_sv};

    std::string id_str;
    {
      std::ostringstream o;
      epee::serialization::dump_as_json(o, id, 0 /*indent*/, false /*newlines*/);
      id_str = o.str();
    }

    // Try to load "params" into a generic epee value; if it fails (because there is no "params")
    // then we will replace it with an empty string to signal that no params were provided.
    if (!ps.get_value("params", epee_stuff.second, nullptr))
      request.body = ""_sv;

    std::string result;
    try {
      result = command.invoke(std::move(request), m_server);
    } catch (const parse_error& e) {
      // This isn't really WARNable as it's the client fault; log at info level instead.
      MINFO("JSON RPC request for '" << method << "' called with invalid data: " << e.what());
      return json_rpc_error(-32602, "Invalid params", body);
    } catch (const std::exception& e) {
      MWARNING("json_rpc '" << method << "' request raised an exception: " << e.what());
      return json_rpc_error(-32603, "Internal error", body);
    } catch (...) {
      MWARNING("json_rpc '" << method << "' request raised an unknown exception");
      return json_rpc_error(-32603, "Internal error", body);
    }

    // The string is pre-serialized JSON.  But epee serialization is garbage so there's no way we
    // can actually JSON serialize this using epee without building a separate wrapper struct for
    // each serializable type, which is just stupid (but that's life with epee and divorce is
    // currently too expensive) so build it ourselves.
    size_t needed = json_rpc_[0].size() + json_rpc_[1].size() + json_rpc_[2].size() + id_str.size() + result.size();
    if (result.capacity() >= needed) {
      // The returned result has enough spare capacity to avoid a reallocation (though we
      // still have to shift the contents).
      auto inner_size = result.size();
      result.resize(needed);
      std::copy_backward(result.begin(), result.begin() + inner_size, result.begin() + (needed - json_rpc_[2].size()));
      body = std::move(result);
    } else {
      // Otherwise we need a new string, so clear and resize it to what we need, then copy in the
      // JSON into the right spot.
      body.clear();
      body.resize(needed);
      std::copy(result.begin(), result.end(), body.begin() + json_rpc_[0].size() + json_rpc_[1].size() + id_str.size());
    }
    // Now copy the prefix, id, and tail into the right locations
    auto bodyit = std::copy(json_rpc_[0].begin(), json_rpc_[0].end(), body.begin()); // Prefix
    bodyit = std::copy(id_str.begin(), id_str.end(), bodyit); // id (right after prefix)
    std::copy(json_rpc_[1].begin(), json_rpc_[1].end(), bodyit); // middle (right after id)
    // json data already copied
    std::copy(json_rpc_[2].begin(), json_rpc_[2].end(), body.begin() + (needed - json_rpc_[2].size())); // tail at the end
    return HTTP_OK;
  }

}} // namespace cryptonote::rpc
