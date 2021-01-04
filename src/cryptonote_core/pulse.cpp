#include <array>
#include <mutex>
#include <chrono>

#include "epee/wipeable_string.h"
#include "epee/memwipe.h"
#include "epee/misc_log_ex.h"
#include "common/random.h"

#include "cryptonote_core.h"
#include "cryptonote_basic/hardfork.h"
#include "gnode_list.h"
#include "gnode_quorum_cop.h"
#include "gnode_rules.h"

extern "C"
{
#include <sodium/crypto_generichash.h>
};

#undef GYUANX_DEFAULT_LOG_CATEGORY
#define GYUANX_DEFAULT_LOG_CATEGORY "pulse"

// Deliberately makes pulse communications flakey for testing purposes:
//#define PULSE_TEST_CODE

enum struct round_state
{
  null_state,
  wait_for_next_block,

  prepare_for_round,
  wait_for_round,

  send_and_wait_for_handshakes,

  send_handshake_bitsets,
  wait_for_handshake_bitsets,

  send_block_template,
  wait_for_block_template,

  send_and_wait_for_random_value_hashes,
  send_and_wait_for_random_value,
  send_and_wait_for_signed_blocks,
};

constexpr std::string_view round_state_string(round_state state)
{
  switch(state)
  {
    case round_state::null_state: return "XX Null State"sv;
    case round_state::wait_for_next_block: return "Wait For Next Block"sv;

    case round_state::prepare_for_round: return "Prepare For Round"sv;
    case round_state::wait_for_round: return "Wait For Round"sv;

    case round_state::send_and_wait_for_handshakes: return "Send & Wait For Handshakes"sv;

    case round_state::send_handshake_bitsets: return "Send Validator Handshake Bitsets"sv;
    case round_state::wait_for_handshake_bitsets: return "Wait For Validator Handshake Bitsets"sv;

    case round_state::send_block_template: return "Send Block Template"sv;
    case round_state::wait_for_block_template: return "Wait For Block Template"sv;

    case round_state::send_and_wait_for_random_value_hashes: return "Send & Wait For Random Value Hash"sv;
    case round_state::send_and_wait_for_random_value: return "Send & Wait For Random Value"sv;
    case round_state::send_and_wait_for_signed_blocks: return "Send & Wait For Signed Blocks"sv;
  }

  return "Invalid2"sv;
}

enum struct sn_type
{
  none,
  producer,
  validator,
};

enum struct queueing_state
{
  empty,
  received,
  processed,
};

template <typename T>
using quorum_array = std::array<T, gnodes::PULSE_QUORUM_NUM_VALIDATORS>;

// Stores message for quorumnet per stage. Some validators may reach later
// stages before we arrive at that stage. To properly validate messages we also
// need to wait until we arrive at the same stage such that we have received all
// the necessary information to do so on Quorumnet.
struct message_queue
{
  quorum_array<std::pair<pulse::message, queueing_state>> buffer;
  size_t count;
};

struct pulse_wait_stage
{
  message_queue     queue;         // For messages from later stages that arrived before we reached that stage
  uint16_t          bitset;        // Bitset of validators that we received a message from for this stage
  uint16_t          msgs_received; // Number of unique messages received in the stage
  pulse::time_point end_time;      // Time at which the stage ends
};

template <typename T>
struct pulse_send_stage
{
  T    data; // Data that must be sent to Nodes via Quorumnet
  bool sent; // When true, data has been sent via Quorumnet once already.

  bool one_time_only()
  {
    if (sent) return false;
    sent = true;
    return true;
  }
};

struct round_history
{
  uint64_t              height;
  uint8_t               round;
  crypto::hash          top_block_hash;
  gnodes::quorum quorum;
};

struct round_context
{
  // Store the recent history of quorums in the past to allow validating late
  // arriving messages and allow printing out the correct response ('error
  // unknown message origin' or 'ok to ignore').
  std::array<round_history, 3> quorum_history;
  size_t                      quorum_history_index;

  struct
  {
    uint64_t          height;              // Current blockchain height that Pulse wants to generate a block for
    crypto::hash      top_hash;            // Latest block hash included in signatures for rejecting out of date nodes
    pulse::time_point round_0_start_time;  // When round 0 should start and subsequent round timings are derived from.
  } wait_for_next_block;

  struct
  {
    bool                  queue_for_next_round; // When set to true, invoking prepare_for_round(...) will wait for (round + 1)
    uint8_t               round;                // The next round the Pulse ceremony will generate a block for
    gnodes::quorum quorum;               // The block producer/validator participating in the next round
    sn_type               participant;          // Is this daemon a block producer, validator or non participant.
    size_t                my_quorum_position;   // Position in the quorum, 0 if producer or neither, or [0, PULSE_QUORUM_NUM_VALIDATORS) if a validator
    std::string           node_name;            // Short-hand string for describing the node in logs, i.e. V[0] for validator 0 or W[0] for the producer.
    pulse::time_point     start_time;           // When the round starts
  } prepare_for_round;

  struct
  {
    struct
    {
      bool sent;               // When true, handshake sent and waiting for other handshakes
      quorum_array<bool> data; // Received data from messages from Quorumnet
      pulse_wait_stage stage;
    } send_and_wait_for_handshakes;

    struct
    {
      quorum_array<std::optional<uint16_t>> data;
      pulse_wait_stage stage;

      uint16_t best_bitset; // The most agreed upon validators for participating in rounds. Value is set when all handshake bitsets are received.
      uint16_t best_count;  // How many validators agreed upon the best bitset.
    } wait_for_handshake_bitsets;

    struct
    {
      cryptonote::block block; // The block template with the best validator bitset and Pulse round applied to it.
      pulse_wait_stage stage;
    } wait_for_block_template;

    struct
    {
      pulse_send_stage<crypto::hash> send;
      struct
      {
        quorum_array<std::optional<crypto::hash>> data;
        pulse_wait_stage stage;
      } wait;
    } random_value_hashes;

    struct
    {
      pulse_send_stage<cryptonote::pulse_random_value> send;

      struct
      {
        quorum_array<std::optional<cryptonote::pulse_random_value>> data;
        pulse_wait_stage stage;
      } wait;
    } random_value;

    struct
    {
      pulse_send_stage<crypto::signature> send;
      cryptonote::block                   final_block;

      struct
      {
        quorum_array<std::optional<crypto::signature>> data;
        pulse_wait_stage stage;
      } wait;
    } signed_block;
  } transient;

  round_state state;
};

static round_context context;
namespace
{

crypto::hash blake2b_hash(void const *data, size_t size)
{
  crypto::hash result = {};
  static_assert(sizeof(result) == crypto_generichash_BYTES);
  crypto_generichash(reinterpret_cast<unsigned char *>(result.data), sizeof(result), reinterpret_cast<unsigned char const *>(data), size, nullptr /*key*/, 0 /*key length*/);
  return result;
}

std::string log_prefix(round_context const &context)
{
  std::stringstream result;
  result << "Pulse B" << context.wait_for_next_block.height << " R";
  if (context.state >= round_state::prepare_for_round)
    result << +context.prepare_for_round.round;
  else
    result << "0";
  result << ": ";

  if (context.prepare_for_round.node_name.size()) result << context.prepare_for_round.node_name << " ";
  result << "'" << round_state_string(context.state) << "' ";
  return result.str();
}

std::bitset<sizeof(uint16_t) * 8> bitset_view16(uint16_t val)
{
  std::bitset<sizeof(uint16_t) * 8> result = val;
  return result;
}

//
// NOTE: pulse::message Utiliities
//
pulse::message msg_init_from_context(round_context const &context)
{
  pulse::message result  = {};
  result.quorum_position = context.prepare_for_round.my_quorum_position;
  result.round           = context.prepare_for_round.round;
  return result;
}

// Generate the hash necessary for signing a message. All fields of the 'msg'
// must have been set for the type of the message except the signature for the
// hash to be generated correctly.
crypto::hash msg_signature_hash(crypto::hash const &top_block_hash, pulse::message const &msg)
{
  crypto::hash result = {};
  switch(msg.type)
  {
    case pulse::message_type::invalid:
      assert("Invalid Code Path" == nullptr);
    break;

    case pulse::message_type::handshake:
    {
      auto buf = tools::memcpy_le(top_block_hash.data, msg.quorum_position, msg.round);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case pulse::message_type::handshake_bitset:
    {
      auto buf = tools::memcpy_le(msg.handshakes.validator_bitset, top_block_hash.data, msg.quorum_position, msg.round);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case pulse::message_type::block_template:
    {
      crypto::hash block_hash = blake2b_hash(msg.block_template.blob.data(), msg.block_template.blob.size());
      auto buf                = tools::memcpy_le(msg.round, block_hash.data);
      result                  = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case pulse::message_type::random_value_hash:
    {
      auto buf = tools::memcpy_le(top_block_hash.data, msg.quorum_position, msg.round, msg.random_value_hash.hash.data);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case pulse::message_type::random_value:
    {
      auto buf = tools::memcpy_le(top_block_hash.data, msg.quorum_position, msg.round, msg.random_value.value.data);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case pulse::message_type::signed_block:
    {
      crypto::signature const &final_signature = msg.signed_block.signature_of_final_block_hash;
      auto buf = tools::memcpy_le(top_block_hash.data, msg.quorum_position, msg.round, final_signature.c.data, final_signature.r.data);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;
  }

  return result;
}

// Generate a helper string that describes the origin of the message, i.e.
// 'Signed Block' at round 2 from 6:f9337ffc8bc30baf3fca92a13fa5a3a7ab7c93e69acb7136906e7feae9d3e769
//   or
// <Message Type> at round <Round> from <Validator Index>:<Validator Public Key>
std::string msg_source_string(round_context const &context, pulse::message const &msg)
{
  if (msg.quorum_position >= context.prepare_for_round.quorum.validators.size()) return "XX";

  std::stringstream stream;
  stream << "'" << message_type_string(msg.type) << " at round " << +msg.round << " from " << msg.quorum_position;
  if (context.state >= round_state::prepare_for_round)
  {
    if (msg.quorum_position < context.prepare_for_round.quorum.validators.size())
    {
      crypto::public_key const &key = context.prepare_for_round.quorum.validators[msg.quorum_position];
      stream << ":" << key;
    }
  }

  return stream.str();
}

bool msg_signature_check(pulse::message const &msg, crypto::hash const &top_block_hash, gnodes::quorum const &quorum, std::string *error)
{
  std::stringstream stream;
  GYUANX_DEFER {
    if (error) *error = stream.str();
  };

  // Get Service Node Key
  crypto::public_key const *key = nullptr;
  switch (msg.type)
  {
    case pulse::message_type::invalid:
    {
      assert("Invalid Code Path" == nullptr);
      if (error) stream << log_prefix(context) << "Unhandled message type '" << pulse::message_type_string(msg.type) << "' can not verify signature.";
      return false;
    }
    break;

    case pulse::message_type::handshake: [[fallthrough]];
    case pulse::message_type::handshake_bitset: [[fallthrough]];
    case pulse::message_type::random_value_hash: [[fallthrough]];
    case pulse::message_type::random_value: [[fallthrough]];
    case pulse::message_type::signed_block:
    {
      if (msg.quorum_position >= static_cast<int>(quorum.validators.size()))
      {
        if (error) stream << log_prefix(context) << "Quorum position " << msg.quorum_position << " in Pulse message indexes oob";
        return false;
      }

      key = &quorum.validators[msg.quorum_position];
    }
    break;

    case pulse::message_type::block_template:
    {
      if (msg.quorum_position != 0)
      {
        if (error) stream << log_prefix(context) << "Quorum position " << msg.quorum_position << " in Pulse message indexes oob";
        return false;
      }

      key = &context.prepare_for_round.quorum.workers[0];
    }
    break;
  }

  if (!crypto::check_signature(msg_signature_hash(top_block_hash, msg), *key, msg.signature))
  {
    if (error) stream << log_prefix(context) << "Signature for " << msg_source_string(context, msg) << " at height " << context.wait_for_next_block.height << "; is invalid";
    return false;
  }

  return true;
}

//
// NOTE: round_context Utilities
//
// Construct a pulse::message for sending the handshake bit or bitset.
void relay_validator_handshake_bit_or_bitset(round_context const &context, void *quorumnet_state, gnodes::gnode_keys const &key, bool sending_bitset)
{
  assert(context.prepare_for_round.participant == sn_type::validator);

  // Message
  pulse::message msg = msg_init_from_context(context);
  if (sending_bitset)
  {
    msg.type = pulse::message_type::handshake_bitset;

    // Generate the bitset from our received handshakes.
    auto const &quorum = context.transient.send_and_wait_for_handshakes.data;
    for (size_t quorum_index = 0; quorum_index < quorum.size(); quorum_index++)
      if (bool received = quorum[quorum_index]; received)
        msg.handshakes.validator_bitset |= (1 << quorum_index);
  }
  else
  {
    msg.type = pulse::message_type::handshake;
  }
  crypto::generate_signature(msg_signature_hash(context.wait_for_next_block.top_hash, msg), key.pub, key.key, msg.signature);
  handle_message(quorumnet_state, msg); // Add our own. We receive our own msg for the first time which also triggers us to relay.
}

// Check the stage's queue for any messages that we received early and process
// them if any. Any messages in the queue that we haven't received yet will also
// be relayed to the quorum.
void handle_messages_received_early_for(pulse_wait_stage &stage, void *quorumnet_state)
{
  if (!stage.queue.count)
    return;

  for (auto &[msg, queued] : stage.queue.buffer)
  {
    if (queued == queueing_state::received)
    {
      pulse::handle_message(quorumnet_state, msg);
      queued = queueing_state::processed;
    }
  }
}

// In Pulse, after the block template and validators are locked in, enforce that
// all participating validators are doing their job in the stage.
bool enforce_validator_participation_and_timeouts(round_context const &context,
                                                  pulse_wait_stage const &stage,
                                                  gnodes::gnode_list &node_list,
                                                  bool timed_out,
                                                  bool all_received)
{
  assert(context.state > round_state::wait_for_handshake_bitsets);
  uint16_t const validator_bitset = context.transient.wait_for_handshake_bitsets.best_bitset;

  if (timed_out && !all_received)
  {
    MDEBUG(log_prefix(context) << "Stage timed out: insufficient responses. Expected "
                               << "(" << bitset_view16(validator_bitset).count() << ") " << bitset_view16(validator_bitset) << " received "
                               << "(" << bitset_view16(stage.bitset).count()     << ") " << bitset_view16(stage.bitset));
    return false;
  }

  // NOTE: This is not technically meant to hit, internal invariant checking
  // that should have been triggered earlier. Enforce validator participation is
  // only called after the stage has ended/timed out.
  bool unexpected_items = (stage.bitset | validator_bitset) != validator_bitset;
  if (stage.msgs_received == 0 || unexpected_items)
  {
    MERROR(log_prefix(context) << "Internal error: expected bitset " << bitset_view16(validator_bitset) << ", but accepted and received " << bitset_view16(stage.bitset));
    return false;
  }

  return true;
}

} // anonymous namespace

void pulse::handle_message(void *quorumnet_state, pulse::message const &msg)
{
  if (context.state < round_state::wait_for_round)
  {
    // TODO(doyle): Handle this better.
    // We are not ready for any messages because we haven't prepared for a round
    // yet (don't have the necessary information yet to validate the message).
    return;
  }

  // TODO(gyuanx): We don't support messages from future rounds. A round
  // mismatch will be detected in the signature as the round is included in the
  // signature hash.

  if (std::string sig_check_err;
      !msg_signature_check(msg, context.wait_for_next_block.top_hash, context.prepare_for_round.quorum, &sig_check_err))
  {
    bool print_err    = true;
    size_t iterations = std::min(context.quorum_history.size(), context.quorum_history_index);
    for (size_t i = 0; i < iterations; i++)
    {
      auto const &past_round = context.quorum_history[i];
      //
      // NOTE: We can't do any filtering on the quorums to check against
      // (like comparing the round in the message with the past_round's round)
      // because the intermediary relayers of this message might have modified
      // it maliciously before propagating it.
      //
      // Hence we check it against all the quorums in history. So keep the
      // number of quorums stored in history very small to keep this fast!
      //

      if (msg_signature_check(msg, past_round.top_block_hash, past_round.quorum, nullptr /*error msg*/))
      {
        // NOTE: This is ok, we detected a round failed earlier than someone else
        // and lingering messages are still going around on Quorumnet from
        // a round in the past.
        //
        // i.e. You were the block producer and have submitted the block template,
        // in which case your role in the ceremony is done and you sleep until
        // the next round/block. Old lingering messages for the block producer
        // (you) might still being propagated, and that is ok, and should not be
        // marked an error, just ignored.

        print_err = false;
        MTRACE(log_prefix(context) << "Received valid message from the past (round " << +msg.round  << "), ignoring");
        break;
      } // else: Message has unknown origins, it is not something we know how to validate.
    }

    if (print_err)
      MERROR(sig_check_err);

    return;
  }

  pulse_wait_stage *stage = nullptr;
  switch(msg.type)
  {
    case pulse::message_type::invalid:
    {
      MTRACE(log_prefix(context) << "Received invalid message type, dropped");
      return;
    }

    case pulse::message_type::handshake:         stage = &context.transient.send_and_wait_for_handshakes.stage; break;
    case pulse::message_type::handshake_bitset:  stage = &context.transient.wait_for_handshake_bitsets.stage;   break;
    case pulse::message_type::block_template:    stage = &context.transient.wait_for_block_template.stage;      break;
    case pulse::message_type::random_value_hash: stage = &context.transient.random_value_hashes.wait.stage;     break;
    case pulse::message_type::random_value:      stage = &context.transient.random_value.wait.stage;            break;
    case pulse::message_type::signed_block:      stage = &context.transient.signed_block.wait.stage;            break;
  }

  bool msg_received_early = false;
  switch(msg.type)
  {
    case pulse::message_type::invalid:           assert("Invalid Code Path" != nullptr); return;
    case pulse::message_type::handshake:         msg_received_early = (context.state < round_state::send_and_wait_for_handshakes);          break;
    case pulse::message_type::handshake_bitset:  msg_received_early = (context.state < round_state::wait_for_handshake_bitsets);            break;
    case pulse::message_type::block_template:    msg_received_early = (context.state < round_state::wait_for_block_template);               break;
    case pulse::message_type::random_value_hash: msg_received_early = (context.state < round_state::send_and_wait_for_random_value_hashes); break;
    case pulse::message_type::random_value:      msg_received_early = (context.state < round_state::send_and_wait_for_random_value);        break;
    case pulse::message_type::signed_block:      msg_received_early = (context.state < round_state::send_and_wait_for_signed_blocks);       break;
  }

  if (msg_received_early) // Enqueue the message until we're ready to process it
  {
    auto &[entry, queued] = stage->queue.buffer[msg.quorum_position];
    if (queued == queueing_state::empty)
    {
      MTRACE(log_prefix(context) << "Message received early " << msg_source_string(context, msg) << ", queueing until we're ready.");
      stage->queue.count++;
      entry  = std::move(msg);
      queued = queueing_state::received;
    }

    return;
  }

  uint16_t const validator_bit = (1 << msg.quorum_position);
  if (context.state > round_state::wait_for_handshake_bitsets &&
      msg.type > pulse::message_type::handshake_bitset)
  {
    // After the validator bitset has been set, the participating validators are
    // locked in. Any stray messages from other validators are rejected.
    if ((validator_bit & context.transient.wait_for_handshake_bitsets.best_bitset) == 0)
    {
      auto bitset_view = bitset_view16(context.transient.wait_for_handshake_bitsets.best_bitset);
      MTRACE(log_prefix(context) << "Dropping " << msg_source_string(context, msg) << ". Not a locked in participant, bitset is " << bitset_view);
      return;
    }
  }

  if (msg.quorum_position >= gnodes::PULSE_QUORUM_NUM_VALIDATORS)
  {
    MTRACE(log_prefix(context) << "Dropping " << msg_source_string(context, msg) << ". Message quorum position indexes oob");
    return;
  }

  //
  // Add Message Data to Pulse Stage
  //
  switch(msg.type)
  {
    case pulse::message_type::invalid:
      assert("Invalid Code Path" != nullptr);
      return;

    case pulse::message_type::handshake:
    {
      auto &quorum = context.transient.send_and_wait_for_handshakes.data;
      if (quorum[msg.quorum_position]) return;
      quorum[msg.quorum_position] = true;
      MTRACE(log_prefix(context) << "Received handshake with quorum position bit (" << msg.quorum_position << ") "
                                 << bitset_view16(validator_bit) << " saved to bitset "
                                 << bitset_view16(stage->bitset));
    }
    break;

    case pulse::message_type::handshake_bitset:
    {
      auto &quorum = context.transient.wait_for_handshake_bitsets.data;
      auto &bitset = quorum[msg.quorum_position];
      if (bitset) return;
      bitset = msg.handshakes.validator_bitset;
    }
    break;

    case pulse::message_type::block_template:
    {
      if (stage->msgs_received == 1)
        return;

      cryptonote::block block = {};
      if (!cryptonote::t_serializable_object_from_blob(block, msg.block_template.blob))
      {
        MTRACE(log_prefix(context) << "Received unparsable pulse block template blob");
        return;
      }

      if (block.pulse.round != context.prepare_for_round.round)
      {
        MTRACE(log_prefix(context) << "Received pulse block template specifying different round " << +block.pulse.round
                                   << ", expected " << +context.prepare_for_round.round);
        return;
      }

      if (block.pulse.validator_bitset != context.transient.wait_for_handshake_bitsets.best_bitset)
      {
        auto block_bitset = bitset_view16(block.pulse.validator_bitset);
        auto our_bitset   = bitset_view16(context.transient.wait_for_handshake_bitsets.best_bitset);
        MTRACE(log_prefix(context) << "Received pulse block template specifying different validator handshake bitsets " << block_bitset << ", expected " << our_bitset);
        return;
      }

      context.transient.wait_for_block_template.block = std::move(block);
    }
    break;

    case pulse::message_type::random_value_hash:
    {
      auto &quorum = context.transient.random_value_hashes.wait.data;
      auto &value  = quorum[msg.quorum_position];
      if (value) return;
      value = msg.random_value_hash.hash;
    }
    break;

    case pulse::message_type::random_value:
    {
      auto &quorum = context.transient.random_value.wait.data;
      auto &value  = quorum[msg.quorum_position];
      if (value) return;

      if (auto const &hash = context.transient.random_value_hashes.wait.data[msg.quorum_position]; hash)
      {
        auto derived = blake2b_hash(msg.random_value.value.data, sizeof(msg.random_value.value.data));
        if (derived != *hash)
        {
          MTRACE(log_prefix(context) << "Dropping " << msg_source_string(context, msg)
                                    << ". Rederived random value hash " << derived << " does not match original hash "
                                    << *hash);
          return;
        }
      }

      value = msg.random_value.value;
    }
    break;

    case pulse::message_type::signed_block:
    {
      // NOTE: The block template with the final random value inserted but no
      // Service Node signatures. (Service Node signatures are added in one shot
      // after this stage has timed out and all signatures are collected).
      cryptonote::block const &final_block_no_signatures = context.transient.signed_block.final_block;
      crypto::hash const final_block_hash                = cryptonote::get_block_hash(final_block_no_signatures);

      assert(msg.quorum_position < context.prepare_for_round.quorum.validators.size());
      crypto::public_key const &validator_key = context.prepare_for_round.quorum.validators[msg.quorum_position];
      if (!crypto::check_signature(final_block_hash, validator_key, msg.signed_block.signature_of_final_block_hash))
      {
        MTRACE(log_prefix(context) << "Dropping " << msg_source_string(context, msg)
                                   << ". Signature signing final block hash "
                                   << msg.signed_block.signature_of_final_block_hash
                                   << " does not validate with the Service Node");
        return;
      }

      auto &quorum    = context.transient.signed_block.wait.data;
      auto &signature = quorum[msg.quorum_position];
      if (signature) return;
      signature = msg.signed_block.signature_of_final_block_hash;
    }
    break;
  }

  stage->bitset |= validator_bit;
  stage->msgs_received++;

  if (quorumnet_state)
    cryptonote::quorumnet_pulse_relay_message_to_quorum(quorumnet_state, msg, context.prepare_for_round.quorum, context.prepare_for_round.participant == sn_type::producer);
}

// TODO(doyle): Update pulse::perpare_for_round with this function after the hard fork and sanity check it on testnet.
bool pulse::convert_time_to_round(pulse::time_point const &time, pulse::time_point const &r0_timestamp, uint8_t *round)
{
  auto const time_since_round_started = time <= r0_timestamp ? std::chrono::seconds(0) : (time - r0_timestamp);
  size_t result_usize                 = time_since_round_started / gnodes::PULSE_ROUND_TIME;
  if (round) *round = static_cast<uint8_t>(result_usize);
  return result_usize <= 255;
}

bool pulse::get_round_timings(cryptonote::Blockchain const &blockchain, uint64_t block_height, uint64_t prev_timestamp, pulse::timings &times)
{
  times = {};
  static uint64_t const hf16_height = blockchain.get_earliest_ideal_height_for_version(cryptonote::network_version_16_pulse);
  if (hf16_height == std::numeric_limits<uint64_t>::max())
    return false;

  if (blockchain.get_current_blockchain_height() < hf16_height)
    return false;

  cryptonote::block genesis_block;
  if (!blockchain.get_block_by_height(hf16_height - 1, genesis_block))
    return false;

  uint64_t const delta_height = block_height - cryptonote::get_block_height(genesis_block);
  times.genesis_timestamp     = pulse::time_point(std::chrono::seconds(genesis_block.timestamp));

  times.prev_timestamp  = pulse::time_point(std::chrono::seconds(prev_timestamp));
  times.ideal_timestamp = pulse::time_point(times.genesis_timestamp + (TARGET_BLOCK_TIME * delta_height));

#if 1
  times.r0_timestamp    = std::clamp(times.ideal_timestamp,
                                  times.prev_timestamp + gnodes::PULSE_MIN_TARGET_BLOCK_TIME,
                                  times.prev_timestamp + gnodes::PULSE_MAX_TARGET_BLOCK_TIME);
#else // NOTE: Debug, make next block start relatively soon
  times.r0_timestamp = times.prev_timestamp + gnodes::PULSE_ROUND_TIME;
#endif

  times.miner_fallback_timestamp = times.r0_timestamp + (gnodes::PULSE_ROUND_TIME * 255);
  return true;
}

/*
  Pulse progresses via a state-machine that is iterated through job submissions
  to 1 dedicated Pulse thread, started by LMQ.

  Iterating the state-machine is done by a periodic invocation of
  pulse::main(...) and messages received via Quorumnet for Pulse, which are
  queued in the thread's job queue.

  Using 1 dedicated thread via LMQ avoids any synchronization required in the
  user code when implementing Pulse.

  Skip control flow graph for textual description of stages.

          +---------------------+
          | Wait For Next Block |<--------+-------+
          +---------------------+         |       |
           |                              |       |
           +-[Blocks for round acquired]--+ No    |
           |                              |       |
           | Yes                          |       |
           |                              |       |
          +---------------------+         |       |
    +---->| Prepare For Round   |         |       |
    |     +---------------------+         |       |
    |      |                              |       |
    |     [Enough SN's for Pulse]---------+ No    |
    |      |                                      |
    |     Yes                                     |
    |      |                                      |
    |     +---------------------+                 |
    |     | Wait For Round      |                 |
    |     +---------------------+                 |
    |      |                                      |
    |     [Block Height Changed?]-----------------+ Yes
    |      |
    |      | No
    |      |
 No +-----[Participating in Quorum?]
    |      |
    |      | Yes
    |      |
    |      |
    |     [Validator?]------------------------------------+ No (We are Block Producer)
    |      |                                              |
    |      | Yes                                          |
    |      |                                              |
    |     +-----------------------------+                 |
    |     | Send And Wait For Handshakes|                 |
    |     +-----------------------------+                 |
    |      |                                              |
Yes +-----[Quorumnet Comm Failure]                        |
    |      |                                              |
    |      | No                                           |
    |      |                                              |
    |     +-----------------------+                       |
    |     | Send Handshake Bitset |                       |
    |     +-----------------------+                       |
    |      |                                              |
Yes +-----[Quorumnet Comm Failure]                        |
    |      |                                              |
    |      | No                                           |
    |      |                                              |
    |     +----------------------------+                  |
    |     | Wait For Handshake Bitsets |<-----------------+
    |     +----------------------------+
    |      |
Yes +-----[Insufficient Bitsets]
    |      |
    |      | No
    |      |
    |     [Block Producer?]-------------------------------+ No (We are a Validator)
    |      |                                              |
    |      | Yes                                          |
    |      |                                              |
    |     +---------------------+                         |
    |     | Send Block Template |                         |
    |     +---------------------+                         |
    |      |                                              |
    +------+ (Block Producer's role is finished)          |
    |                                                     |
    |                                                     |
    |     +-------------------------+                     |
    |     | Wait For Block Template |<--------------------+
    |     +-------------------------+
    |      |
Yes +-----[Timed Out Waiting for Template]
    |      |
    |      | No
    |      |
    |     +---------------------------------------+
    |     | Send And Wait For Random Value Hashes |
    |     +---------------------------------------+
    |      |
Yes +-----[Insufficient Hashes]
    |      |
    |      | No
    |      |
    |     +--------------------------------+
    |     | Send And Wait For Random Value |
    |     +--------------------------------+
    |      |
Yes +-----[Insufficient Values]
    |      |
    |      | No
    |      |
    |     +---------------------------------+
    |     | Send And Wait For Signed Blocks |
    |     +---------------------------------+
    |      |
Yes +-----[Block can not be added to blockchain]
           |
           | No
           |
           + (Finished, state machine resets)

  Wait For Next Block:
    - Waits for the next block in the blockchain to arrive

    - Retrieves the blockchain metadata for starting a Pulse Round including the
      Genesis Pulse Block for the base timestamp and the top block hash and
      height for signatures.

    - // TODO(gyuanx): After the Genesis Pulse Block is checkpointed, we can
      // remove it from the event loop. Right now we recheck every block incase
      // of (the very unlikely event) reorgs that might change the block at the
      // hardfork.

    - The ideal next block timestamp is determined by

      G.Timestamp + (height * TARGET_BLOCK_TIME)

      Where 'G' is the base Pulse genesis block, i.e. the hardforking block
      activating Pulse (HF16).

      The actual next block timestamp is determined by

      P.Timestamp + (TARGET_BLOCK_TIME ±15s)

      Where 'P' is the previous block. The block time is adjusted ±15s depending
      on how close/far away the ideal block time is.

  Prepare For Round:
    - Generate data for executing the round such as the Quorum and stage
      durations depending on the round Pulse is at by comparing the clock with
      the ideal block timestamp.

    - The state machine *always* reverts to 'Prepare For Round' when any
      subsequent stage fails, except in the cases where Pulse can not proceed
      because of an insufficient Service Node network.

    - If the next round to prepare for is >255, we disable Pulse and re-allow
      PoW blocks to be added to the chain, the Pulse state machine resets and
      waits for the next block to arrive and re-evaluates if Pulse is possible
      again.

  Wait For Round (Block Producer & Validator)
    - Checks clock against the next expected Pulse timestamps has arrived,
      otherwise continues sleeping.

    - If we are a validator we 'Submit Handshakes' with other Validators
      If we are a block producer we skip to 'Wait For Handshake Bitset' and
      await the final handshake bitsets from all the Validators
      Otherwise we return to 'Prepare For Round' and sleep.

  Send And Wait For Handshakes (Validator)
    - On first invocation, we send the handshakes to Validator peers, then waits
      for handshakes. Validators handshake to confirm participation in the round
      and collect other handshakes.

  Send Handshake Bitset (Validator)
    - Send our collected participation bitset to the validators

  Wait For Handshake Bitsets (Block Producer & Validator)
    - Upon receipt, the most common agreed upon bitset is used to lock in
      participation for the round. The round proceeds if more than 60% of the
      validators are participating, the round fails otherwise and reverts to
      'Prepare For Round'.

    - If we are a validator      we go to 'Wait For Block Template'
    - If we are a block producer we go to 'Submit Block Template'

  Submit Block Template (Block Producer)
    - Block producer signs the block template with the validator bitset and
      pulse round applied to the block and sends it to the round validators

    - The block producer is finished for the round and awaits the next
      round (if any subsequent stage fails) or block.

  Wait For Block Template (Validator)
    - Await the block template and ensure it's signed by the block producer, if
      not we revert to 'Prepare For Round'

    - We generate our part of the random value and prepare the hash of the
      random value and proceed to the next stage.

  Send And Wait For Random Value Hashes (Validator)
    - On first invcation, send the hash of our random value prepared in the
      'Wait For Block Template' stage, followed by waiting for the other random
      value hashes from validators.

    - If not all hashes are received according to the locked in validator bitset
      in the block, we revert to 'Prepare For Round'.

  Send And Wait For Random Value (Validator)
    - On first invcation, send the random value prepared in the 'Wait For Block
      Template' stage, followed by waiting for the other random values from
      validators.

    - If not all values are received according to the locked in validator bitset
      in the block, we revert to 'Prepare For Round'.

  Send And Wait For Signed Block (Validator)
    - On first invcation, send our signature, signing the block template with
      all the random values combined into 1 to other validators and await for
      the other signatures to arrive.

    - Ensure the signature signs the same block template we received at the
      beginning from the Block Producer.

    - If not all values are received according to the locked in validator bitset
      in the block, we revert to 'Prepare For Round'.

    - Add the block to the blockchain and on success, that will automatically
      begin propagating the block via P2P. The signatures in the block are added
      in any order, as soon as the first N signatures arrive the block can be
      P2P-ed.
*/

round_state goto_preparing_for_next_round(round_context &context)
{
  context.prepare_for_round.queue_for_next_round = true;
  return round_state::prepare_for_round;
}

void clear_round_data(round_context &context)
{
  if (gnodes::verify_pulse_quorum_sizes(context.prepare_for_round.quorum))
  {
    // NOTE: Store the quorum into history before deleting it from memory.
    // This way we can verify late arriving messages when we may have progressed
    // already into a new round/block.

    bool store        = true;
    size_t iterations = std::min(context.quorum_history.size(), context.quorum_history_index);
    for (size_t i = 0; i < iterations; i++)
    {
      auto &quorum = context.quorum_history[i];
      if (quorum.height == context.wait_for_next_block.height &&
          quorum.round == context.prepare_for_round.round)
      {
        store = false; // Already stored quorum
        break;
      }
    }

    if (store)
    {
      size_t real_quorum_history_index = context.quorum_history_index % context.quorum_history.size();
      context.quorum_history_index++;

      round_history &entry = context.quorum_history[real_quorum_history_index];
      entry                = {};

      entry.top_block_hash = context.wait_for_next_block.top_hash;
      entry.height         = context.wait_for_next_block.height;
      entry.round          = context.prepare_for_round.round;
      entry.quorum         = std::move(context.prepare_for_round.quorum);
    }
  }

  context.transient = {};
  cryptonote::pulse_random_value &old_random_value = context.transient.random_value.send.data;
  auto &old_random_values_array                    = context.transient.random_value.wait.data;
  memwipe(old_random_value.data, sizeof(old_random_value));
  memwipe(old_random_values_array.data(), old_random_values_array.size() * sizeof(old_random_values_array[0]));
  context.prepare_for_round = {};
}

round_state goto_wait_for_next_block_and_clear_round_data(round_context &context)
{
  clear_round_data(context);
  return round_state::wait_for_next_block;
}

round_state wait_for_next_block(uint64_t hf16_height, round_context &context, cryptonote::Blockchain const &blockchain)
{
  //
  // NOTE: If already processing pulse for height, wait for next height
  //
  uint64_t chain_height = blockchain.get_current_blockchain_height(true /*lock*/);
  if (context.wait_for_next_block.height == chain_height)
  {
    for (static uint64_t last_height = 0; last_height != chain_height; last_height = chain_height)
      MDEBUG(log_prefix(context) << "Network is currently producing block " << chain_height << ", waiting until next block");
    return round_state::wait_for_next_block;
  }

  crypto::hash prev_hash = blockchain.get_block_id_by_height(chain_height - 1);
  if (prev_hash == crypto::null_hash)
  {
    for (static uint64_t last_height = 0; last_height != chain_height; last_height = chain_height)
      MDEBUG(log_prefix(context) << "Failed to query the block hash for height " << chain_height - 1);
    return round_state::wait_for_next_block;
  }

  uint64_t prev_timestamp = 0;
  try
  {
    prev_timestamp = blockchain.get_db().get_block_timestamp(chain_height - 1);
  }
  catch(std::exception const &e)
  {
    for (static uint64_t last_height = 0; last_height != chain_height; last_height = chain_height)
      MDEBUG(log_prefix(context) << "Failed to query the block hash for height " << chain_height - 1);
    return round_state::wait_for_next_block;
  }

  pulse::timings times = {};
  if (!get_round_timings(blockchain, chain_height, prev_timestamp, times))
  {
    for (static uint64_t last_height = 0; last_height != chain_height; last_height = chain_height)
      MERROR(log_prefix(context) << "Failed to query the block data for Pulse timings");
    return round_state::wait_for_next_block;
  }

  context.wait_for_next_block.round_0_start_time = times.r0_timestamp;
  context.wait_for_next_block.height             = chain_height;
  context.wait_for_next_block.top_hash           = prev_hash;
  context.prepare_for_round                      = {};

  return round_state::prepare_for_round;
}

round_state prepare_for_round(round_context &context, gnodes::gnode_keys const &key, cryptonote::Blockchain const &blockchain)
{
  //
  // NOTE: Clear Round Data
  //
  {
    // Store values
    uint8_t round             = context.prepare_for_round.round;
    bool queue_for_next_round = context.prepare_for_round.queue_for_next_round;

    clear_round_data(context);

    // Restore values
    context.prepare_for_round.round                = round;
    context.prepare_for_round.queue_for_next_round = queue_for_next_round;
  }

  if (context.prepare_for_round.queue_for_next_round)
  {
    if (context.prepare_for_round.round >= 255)
    {
      // If the next round overflows, we consider the network stalled. Wait for
      // the next block and allow PoW to return.
      return goto_wait_for_next_block_and_clear_round_data(context);
    }

    // Also check if the blockchain has changed, in which case we stop and
    // restart Pulse stages.
    if (context.wait_for_next_block.height != blockchain.get_current_blockchain_height(true /*lock*/))
      return goto_wait_for_next_block_and_clear_round_data(context);

    // 'queue_for_next_round' is set when an intermediate Pulse stage has failed
    // and the caller requests us to wait until the next round to occur.
    context.prepare_for_round.queue_for_next_round = false;
    context.prepare_for_round.round++;
  }

  //
  // NOTE: Check Current Round
  //
  {
    auto now                     = pulse::clock::now();
    auto const time_since_block  = now <= context.wait_for_next_block.round_0_start_time ? std::chrono::seconds(0) : (now - context.wait_for_next_block.round_0_start_time);
    size_t round_usize           = time_since_block / gnodes::PULSE_ROUND_TIME;

    if (round_usize > 255) // Network stalled
    {
      MINFO(log_prefix(context) << "Pulse has timed out, reverting to accepting miner blocks only.");
      return goto_wait_for_next_block_and_clear_round_data(context);
    }

    uint8_t curr_round = static_cast<uint8_t>(round_usize);
    if (curr_round > context.prepare_for_round.round)
      context.prepare_for_round.round = curr_round;
  }

  {
    using namespace gnodes;
    context.prepare_for_round.start_time                          = context.wait_for_next_block.round_0_start_time                + (context.prepare_for_round.round * PULSE_ROUND_TIME);
    context.transient.send_and_wait_for_handshakes.stage.end_time = context.prepare_for_round.start_time                          + PULSE_WAIT_FOR_HANDSHAKES_DURATION;
    context.transient.wait_for_handshake_bitsets.stage.end_time   = context.transient.send_and_wait_for_handshakes.stage.end_time + PULSE_WAIT_FOR_OTHER_VALIDATOR_HANDSHAKES_DURATION;
    context.transient.wait_for_block_template.stage.end_time      = context.transient.wait_for_handshake_bitsets.stage.end_time   + PULSE_WAIT_FOR_BLOCK_TEMPLATE_DURATION;
    context.transient.random_value_hashes.wait.stage.end_time     = context.transient.wait_for_block_template.stage.end_time      + PULSE_WAIT_FOR_RANDOM_VALUE_HASH_DURATION;
    context.transient.random_value.wait.stage.end_time            = context.transient.random_value_hashes.wait.stage.end_time     + PULSE_WAIT_FOR_RANDOM_VALUE_DURATION;
    context.transient.signed_block.wait.stage.end_time            = context.transient.random_value.wait.stage.end_time            + PULSE_WAIT_FOR_SIGNED_BLOCK_DURATION;
  }

  std::vector<crypto::hash> const entropy = gnodes::get_pulse_entropy_for_next_block(blockchain.get_db(), context.wait_for_next_block.top_hash, context.prepare_for_round.round);
  auto const active_node_list             = blockchain.get_gnode_list().active_gnodes_infos();
  uint8_t const hf_version                = blockchain.get_current_hard_fork_version();
  crypto::public_key const &block_leader  = blockchain.get_gnode_list().get_block_leader().key;

  context.prepare_for_round.quorum =
      gnodes::generate_pulse_quorum(blockchain.nettype(),
                                           block_leader,
                                           hf_version,
                                           active_node_list,
                                           entropy,
                                           context.prepare_for_round.round);

  if (!gnodes::verify_pulse_quorum_sizes(context.prepare_for_round.quorum))
  {
    MINFO(log_prefix(context) << "Insufficient Service Nodes to execute Pulse on height " << context.wait_for_next_block.height << ", we require a PoW miner block. Sleeping until next block.");
    return goto_wait_for_next_block_and_clear_round_data(context);
  }

  MDEBUG(log_prefix(context) << "Generate Pulse quorum: " << context.prepare_for_round.quorum);

  //
  // NOTE: Quorum participation
  //
  if (key.pub == context.prepare_for_round.quorum.workers[0])
  {
    // NOTE: Producer doesn't send handshakes, they only collect the
    // handshake bitsets from the other validators to determine who to
    // lock in for this round in the block template.
    context.prepare_for_round.participant = sn_type::producer;
    context.prepare_for_round.node_name   = "W[0]";
  }
  else
  {
    for (size_t index = 0; index < context.prepare_for_round.quorum.validators.size(); index++)
    {
      auto const &validator_key = context.prepare_for_round.quorum.validators[index];
      if (validator_key == key.pub)
      {
        context.prepare_for_round.participant        = sn_type::validator;
        context.prepare_for_round.my_quorum_position = index;
        context.prepare_for_round.node_name = "V[" + std::to_string(context.prepare_for_round.my_quorum_position) + "]";
        break;
      }
    }
  }

  return round_state::wait_for_round;
}

round_state wait_for_round(round_context &context, cryptonote::Blockchain const &blockchain)
{
  const auto curr_height = blockchain.get_current_blockchain_height(true /*lock*/);
  if (context.wait_for_next_block.height != curr_height)
  {
    MDEBUG(log_prefix(context) << "Block height changed whilst waiting for round " << +context.prepare_for_round.round << ", restarting Pulse stages");
    return goto_wait_for_next_block_and_clear_round_data(context);
  }

  auto start_time = context.prepare_for_round.start_time;
  if (auto now = pulse::clock::now(); now < start_time)
  {
    for (static uint64_t last_height = 0; last_height != context.wait_for_next_block.height; last_height = context.wait_for_next_block.height)
      MINFO(log_prefix(context) << "Waiting for round " << +context.prepare_for_round.round << " to start in " << tools::friendly_duration(start_time - now));
    return round_state::wait_for_round;
  }

#ifdef PULSE_TEST_CODE
  // For testing purposes: we apply possible random non-response and random delays to half of all
  // blocks; we go in batches of 10: 10 maybe-faulty blocks followed by 10 well-behaved blocks.
  // (Faulty blocks have an odd second-last height digit).
  if (curr_height % 20 >= 10)
  {
    size_t faulty_chance = tools::uniform_distribution_portable(tools::rng, 100);
    if (faulty_chance < 10)
    {
      MDEBUG(log_prefix(context) << "FAULTY NODE ACTIVATED");
      return goto_preparing_for_next_round(context);
    }

    size_t sleep_chance = tools::uniform_distribution_portable(tools::rng, 100);
    if (sleep_chance < 10)
    {
      auto sleep_time = std::chrono::seconds(tools::uniform_distribution_portable(tools::rng, 20));
      std::this_thread::sleep_for(sleep_time);
      MDEBUG(log_prefix(context) << "SLEEP TIME ACTIVATED " << tools::to_seconds(sleep_time) << "s");
    }
  }
#endif

  if (context.prepare_for_round.participant == sn_type::validator)
  {
    MINFO(log_prefix(context) << "We are a pulse validator, sending handshake bit and collecting other handshakes.");
    return round_state::send_and_wait_for_handshakes;
  }
  else if (context.prepare_for_round.participant == sn_type::producer)
  {
    MINFO(log_prefix(context) << "We are the block producer for height " << context.wait_for_next_block.height << " in round " << +context.prepare_for_round.round << ", awaiting handshake bitsets.");
    return round_state::wait_for_handshake_bitsets;
  }
  else
  {
    MDEBUG(log_prefix(context) << "Non-participant for round, waiting on next round or block.");
    return goto_preparing_for_next_round(context);
  }
}

round_state send_and_wait_for_handshakes(round_context &context, void *quorumnet_state, gnodes::gnode_keys const &key)
{
  //
  // NOTE: Send
  //
  assert(context.prepare_for_round.participant == sn_type::validator);
  if (!context.transient.send_and_wait_for_handshakes.sent)
  {
    context.transient.send_and_wait_for_handshakes.sent = true;
    try
    {
      relay_validator_handshake_bit_or_bitset(context, quorumnet_state, key, false /*sending_bitset*/);
    }
    catch (std::exception const &e)
    {
      MERROR(log_prefix(context) << "Attempting to invoke and send a Pulse participation handshake unexpectedly failed. " << e.what());
      return goto_preparing_for_next_round(context);
    }
  }

  //
  // NOTE: Wait
  //
  handle_messages_received_early_for(context.transient.send_and_wait_for_handshakes.stage, quorumnet_state);
  pulse_wait_stage const &stage = context.transient.send_and_wait_for_handshakes.stage;

  auto const &quorum            = context.transient.send_and_wait_for_handshakes.data;
  bool const timed_out          = pulse::clock::now() >= stage.end_time;
  bool const all_handshakes     = stage.msgs_received == quorum.size();

  assert(context.prepare_for_round.participant == sn_type::validator);
  assert(context.prepare_for_round.my_quorum_position < quorum.size());

  if (all_handshakes || timed_out)
  {
    bool missing_handshakes = timed_out && !all_handshakes;
    MINFO(log_prefix(context) << "Collected validator handshakes " << bitset_view16(stage.bitset) << (missing_handshakes ? ", we timed out and some handshakes were not seen! " : ". ") << "Sending handshake bitset and collecting other validator bitsets.");
    return round_state::send_handshake_bitsets;
  }
  else
  {
    return round_state::send_and_wait_for_handshakes;
  }
}

round_state send_handshake_bitsets(round_context &context, void *quorumnet_state, gnodes::gnode_keys const &key)
{
  try
  {
    relay_validator_handshake_bit_or_bitset(context, quorumnet_state, key, true /*sending_bitset*/);
    return round_state::wait_for_handshake_bitsets;
  }
  catch(std::exception const &e)
  {
    MERROR(log_prefix(context) << "Attempting to invoke and send a Pulse validator bitset unexpectedly failed. " << e.what());
    return goto_preparing_for_next_round(context);
  }
}

round_state wait_for_handshake_bitsets(round_context &context, gnodes::gnode_list &node_list, void *quorumnet_state, gnodes::gnode_keys const &key)
{
  handle_messages_received_early_for(context.transient.wait_for_handshake_bitsets.stage, quorumnet_state);
  pulse_wait_stage const &stage = context.transient.wait_for_handshake_bitsets.stage;

  auto const &quorum     = context.transient.wait_for_handshake_bitsets.data;
  bool const timed_out   = pulse::clock::now() >= stage.end_time;
  bool const all_bitsets = stage.msgs_received == quorum.size();

  if (timed_out || all_bitsets)
  {
    std::map<uint16_t, int> most_common_bitset;
    uint16_t best_bitset = 0;
    size_t count         = 0;
    for (size_t quorum_index = 0; quorum_index < quorum.size(); quorum_index++)
    {
      auto &bitset = quorum[quorum_index];
      if (bitset)
      {
        uint16_t num = ++most_common_bitset[*bitset];
        if (num > count)
        {
          best_bitset = *bitset;
          count       = num;
        }
        MTRACE(log_prefix(context) << "Collected from V[" << quorum_index << "], handshake bitset " << bitset_view16(*bitset));
      }
    }

    bool i_am_not_participating = false;
    if (best_bitset != 0 && context.prepare_for_round.participant == sn_type::validator)
      i_am_not_participating = ((best_bitset & (1 << context.prepare_for_round.my_quorum_position)) == 0);

    if (count < gnodes::PULSE_BLOCK_REQUIRED_SIGNATURES || best_bitset == 0 || i_am_not_participating)
    {
      if (best_bitset == 0)
      {
        // Less than the threshold of the validators can come to agreement about
        // which validators are online, we wait until the next round.
        MDEBUG(log_prefix(context) << count << "/" << quorum.size()
                                   << " validators did not send any handshake bitset or sent an empty handshake "
                                      "bitset and have failed to come to agreement. Waiting until next round.");
      }
      else if (i_am_not_participating)
      {
        MDEBUG(log_prefix(context) << "The participating validator bitset " << bitset_view16(best_bitset)
                                   << " does not include us (quorum index " << context.prepare_for_round.my_quorum_position << "). Waiting until next round.");
      }
      else
      {
        // Can't come to agreement, see threshold comment above
        MDEBUG(log_prefix(context) << "We heard back from less than " << gnodes::PULSE_BLOCK_REQUIRED_SIGNATURES << " of the validators ("
                                   << count << "/" << quorum.size() << "). Waiting until next round.");
      }

      return goto_preparing_for_next_round(context);
    }

    context.transient.wait_for_handshake_bitsets.best_bitset = best_bitset;
    context.transient.wait_for_handshake_bitsets.best_count  = count;
    MINFO(log_prefix(context) << count << "/" << quorum.size()
                              << " validators agreed on the participating nodes in the quorum " << bitset_view16(best_bitset)
                              << (context.prepare_for_round.participant == sn_type::producer
                                      ? ""
                                      : ". Awaiting block template from block producer"));

    if (context.prepare_for_round.participant == sn_type::producer)
      return round_state::send_block_template;
    else
      return round_state::wait_for_block_template;
  }

  return round_state::wait_for_handshake_bitsets;
}

round_state send_block_template(round_context &context, void *quorumnet_state, gnodes::gnode_keys const &key, cryptonote::Blockchain &blockchain)
{
  assert(context.prepare_for_round.participant == sn_type::producer);
  std::vector<gnodes::gnode_pubkey_info> list_state = blockchain.get_gnode_list().get_gnode_list_state({key.pub});

  // Invariants
  if (list_state.empty())
  {
    MWARNING(log_prefix(context) << "Block producer (us) is not available on the service node list, waiting until next round");
    return goto_preparing_for_next_round(context);
  }

  std::shared_ptr<const gnodes::gnode_info> info = list_state[0].info;
  if (!info->is_active())
  {
    MWARNING(log_prefix(context) << "Block producer (us) is not an active service node, waiting until next round");
    return goto_preparing_for_next_round(context);
  }

  // Block
  cryptonote::block block = {};
  {
    uint64_t height                              = 0;
    gnodes::payout block_producer_payouts = gnodes::gnode_info_to_payout(key.pub, *info);
    if (!blockchain.create_next_pulse_block_template(block,
                                                     block_producer_payouts,
                                                     context.prepare_for_round.round,
                                                     context.transient.wait_for_handshake_bitsets.best_bitset,
                                                     height))
    {
      MERROR(log_prefix(context) << "Failed to generate a block template, waiting until next round");
      return goto_preparing_for_next_round(context);
    }

    if (context.wait_for_next_block.height != height)
    {
      MDEBUG(log_prefix(context) << "Block height changed whilst preparing block template for round " << +context.prepare_for_round.round << ", restarting Pulse stages");
      return goto_wait_for_next_block_and_clear_round_data(context);
    }
  }

  // Message
  pulse::message msg      = msg_init_from_context(context);
  msg.type                = pulse::message_type::block_template;
  msg.block_template.blob = cryptonote::t_serializable_object_to_blob(block);
  crypto::generate_signature(msg_signature_hash(context.wait_for_next_block.top_hash, msg), key.pub, key.key, msg.signature);

  // Send
  MINFO(log_prefix(context) << "Validators are handshaken and ready, sending block template from producer (us) to validators.\n" << cryptonote::obj_to_json_str(block));
  cryptonote::quorumnet_pulse_relay_message_to_quorum(quorumnet_state, msg, context.prepare_for_round.quorum, true /*block_producer*/);
  return goto_preparing_for_next_round(context);
}

round_state wait_for_block_template(round_context &context, gnodes::gnode_list &node_list, void *quorumnet_state, gnodes::gnode_keys const &key, cryptonote::Blockchain &blockchain)
{
  handle_messages_received_early_for(context.transient.wait_for_block_template.stage, quorumnet_state);
  pulse_wait_stage const &stage = context.transient.wait_for_block_template.stage;

  assert(context.prepare_for_round.participant == sn_type::validator);
  bool timed_out = pulse::clock::now() >= context.transient.wait_for_block_template.stage.end_time;
  bool received = context.transient.wait_for_block_template.stage.msgs_received == 1;
  if (timed_out || received)
  {
    if (received)
    {
      cryptonote::block const &block = context.transient.wait_for_block_template.block;
      MINFO(log_prefix(context) << "Valid block received: " << cryptonote::obj_to_json_str(context.transient.wait_for_block_template.block));

      // Generate my random value and its hash
      crypto::generate_random_bytes_thread_safe(sizeof(context.transient.random_value.send.data), context.transient.random_value.send.data.data);
      context.transient.random_value_hashes.send.data = blake2b_hash(&context.transient.random_value.send.data, sizeof(context.transient.random_value.send.data));
      return round_state::send_and_wait_for_random_value_hashes;
    }
    else
    {
      MINFO(log_prefix(context) << "Timed out, block template was not received");
      return goto_preparing_for_next_round(context);
    }
  }

  return round_state::wait_for_block_template;
}

round_state send_and_wait_for_random_value_hashes(round_context &context, gnodes::gnode_list &node_list, void *quorumnet_state, gnodes::gnode_keys const &key)
{
  assert(context.prepare_for_round.participant == sn_type::validator);

  //
  // NOTE: Send
  //
  if (context.transient.random_value_hashes.send.one_time_only())
  {
    // Message
    pulse::message msg         = msg_init_from_context(context);
    msg.type                   = pulse::message_type::random_value_hash;
    msg.random_value_hash.hash = context.transient.random_value_hashes.send.data;
    crypto::generate_signature(msg_signature_hash(context.wait_for_next_block.top_hash, msg), key.pub, key.key, msg.signature);
    handle_message(quorumnet_state, msg); // Add our own. We receive our own msg for the first time which also triggers us to relay.
  }

  //
  // NOTE: Wait
  //
  handle_messages_received_early_for(context.transient.random_value_hashes.wait.stage, quorumnet_state);
  pulse_wait_stage const &stage = context.transient.random_value_hashes.wait.stage;

  auto const &quorum    = context.transient.random_value_hashes.wait.data;
  bool const timed_out  = pulse::clock::now() >= stage.end_time;
  bool const all_hashes = stage.bitset == context.transient.wait_for_handshake_bitsets.best_bitset;

  if (timed_out || all_hashes)
  {
    if (!enforce_validator_participation_and_timeouts(context, stage, node_list, timed_out, all_hashes))
      return goto_preparing_for_next_round(context);

    MINFO(log_prefix(context) << "Received " << bitset_view16(stage.bitset).count() << " random value hashes from " << bitset_view16(stage.bitset) << (timed_out ? ". We timed out and some hashes are missing" : ""));
    return round_state::send_and_wait_for_random_value;
  }

  return round_state::send_and_wait_for_random_value_hashes;
}

round_state send_and_wait_for_random_value(round_context &context, gnodes::gnode_list &node_list, void *quorumnet_state, gnodes::gnode_keys const &key)
{
  //
  // NOTE: Send
  //
  assert(context.prepare_for_round.participant == sn_type::validator);
  if (context.transient.random_value.send.one_time_only())
  {
    // Message
    pulse::message msg     = msg_init_from_context(context);
    msg.type               = pulse::message_type::random_value;
    msg.random_value.value = context.transient.random_value.send.data;
    crypto::generate_signature(msg_signature_hash(context.wait_for_next_block.top_hash, msg), key.pub, key.key, msg.signature);
    handle_message(quorumnet_state, msg); // Add our own. We receive our own msg for the first time which also triggers us to relay.
  }

  //
  // NOTE: Wait
  //
  handle_messages_received_early_for(context.transient.random_value.wait.stage, quorumnet_state);
  pulse_wait_stage const &stage = context.transient.random_value.wait.stage;

  auto const &quorum    = context.transient.random_value.wait.data;
  bool const timed_out  = pulse::clock::now() >= stage.end_time;
  bool const all_values = stage.bitset == context.transient.wait_for_handshake_bitsets.best_bitset;

  if (timed_out || all_values)
  {
    if (!enforce_validator_participation_and_timeouts(context, stage, node_list, timed_out, all_values))
      return goto_preparing_for_next_round(context);

    // Generate Final Random Value
    crypto::hash final_hash = {};
    {
      unsigned char constexpr key[crypto_generichash_KEYBYTES] = {};
      crypto_generichash_state state = {};
      crypto_generichash_init(&state, key, sizeof(key), sizeof(final_hash));

      for (size_t index = 0; index < quorum.size(); index++)
      {
        if (auto &random_value = quorum[index]; random_value)
        {
          epee::wipeable_string string = gyuanxmq::to_hex(tools::view_guts(random_value->data));

#if defined(NDEBUG)
          // Mask the random value generated incase someone is snooping logs
          // trying to derive the Service Node rng seed.
          for (int i = 2; i < static_cast<int>(string.size()) - 2; i++)
            string.data()[i] = '.';
#endif

          MDEBUG(log_prefix(context) << "Final random value seeding with V[" << index << "] " << string.view());
          crypto_generichash_update(&state, random_value->data, sizeof(random_value->data));
        }
      }

      crypto_generichash_final(&state, reinterpret_cast<unsigned char *>(final_hash.data), sizeof(final_hash));
    }

    // Add final random value to the block
    context.transient.signed_block.final_block = std::move(context.transient.wait_for_block_template.block);
    cryptonote::block &final_block             = context.transient.signed_block.final_block;
    static_assert(sizeof(final_hash) >= sizeof(final_block.pulse.random_value.data));
    std::memcpy(final_block.pulse.random_value.data, final_hash.data, sizeof(final_block.pulse.random_value.data));

    // Generate the signature of the final block (without any of the other
    // Service Node signatures because we allow the first
    // 'PULSE_BLOCK_REQUIRED_SIGNATURES' that arrive to be added. These can be
    // inconsistent between syncing clients, as long as the signature itself is
    // valid against the quorum Service Nodes).
    crypto::hash const &final_block_hash = cryptonote::get_block_hash(final_block);
    crypto::generate_signature(final_block_hash, key.pub, key.key, context.transient.signed_block.send.data);

    MINFO(log_prefix(context) << "Block final random value " << gyuanxmq::to_hex(tools::view_guts(final_block.pulse.random_value.data)) << " generated from validators " << bitset_view16(stage.bitset));
    return round_state::send_and_wait_for_signed_blocks;
  }

  return round_state::send_and_wait_for_random_value;
}

round_state send_and_wait_for_signed_blocks(round_context &context, gnodes::gnode_list &node_list, void *quorumnet_state, gnodes::gnode_keys const &key, cryptonote::core &core)
{
  assert(context.prepare_for_round.participant == sn_type::validator);

  //
  // NOTE: Send
  //
  if (context.transient.signed_block.send.one_time_only())
  {
    // Message
    pulse::message msg                             = msg_init_from_context(context);
    msg.type                                       = pulse::message_type::signed_block;
    msg.signed_block.signature_of_final_block_hash = context.transient.signed_block.send.data;
    crypto::generate_signature(msg_signature_hash(context.wait_for_next_block.top_hash, msg), key.pub, key.key, msg.signature);
    handle_message(quorumnet_state, msg); // Add our own. We receive our own msg for the first time which also triggers us to relay.
  }

  //
  // NOTE: Wait
  //
  handle_messages_received_early_for(context.transient.signed_block.wait.stage, quorumnet_state);
  pulse_wait_stage const &stage = context.transient.signed_block.wait.stage;

  auto const &quorum   = context.transient.signed_block.wait.data;
  bool const timed_out = pulse::clock::now() >= stage.end_time;
  bool const enough    = stage.bitset >= context.transient.wait_for_handshake_bitsets.best_bitset;

  if (timed_out || enough)
  {
    if (!enforce_validator_participation_and_timeouts(context, stage, node_list, timed_out, enough))
      return goto_preparing_for_next_round(context);

    // Select signatures randomly so we don't always just take the first N required signatures.
    // Then sort just the first N required signatures, so signatures are added
    // to the block in sorted order, but were chosen randomly.
    std::array<size_t, gnodes::PULSE_QUORUM_NUM_VALIDATORS> indices = {};
    size_t indices_count = 0;

    // Pull out indices where we've received a signature
    for (size_t index = 0; index < quorum.size(); index++)
      if (quorum[index])
        indices[indices_count++] = index;

    // Random select from first 'N' PULSE_BLOCK_REQUIRED_SIGNATURES from indices_count entries.
    assert(indices_count >= gnodes::PULSE_BLOCK_REQUIRED_SIGNATURES);
    std::array<size_t, gnodes::PULSE_BLOCK_REQUIRED_SIGNATURES> selected = {};
    std::sample(indices.begin(), indices.begin() + indices_count, selected.begin(), selected.size(), tools::rng);

    // Add Signatures
    cryptonote::block &final_block = context.transient.signed_block.final_block;
    for (size_t index = 0; index < gnodes::PULSE_BLOCK_REQUIRED_SIGNATURES; index++)
    {
      uint16_t validator_index = indices[index];
      auto const &signature    = quorum[validator_index];
      assert(signature);
      MDEBUG(log_prefix(context) << "Signature added: " << validator_index << ":" << context.prepare_for_round.quorum.validators[validator_index] << ", " << *signature);
      final_block.signatures.emplace_back(validator_index, *signature);
    }

    // Propagate Final Block
    MDEBUG(log_prefix(context) << "Final signed block constructed\n" << cryptonote::obj_to_json_str(final_block));
    cryptonote::block_verification_context bvc = {};
    if (!core.handle_block_found(final_block, bvc))
      return goto_preparing_for_next_round(context);

    return goto_wait_for_next_block_and_clear_round_data(context);
  }

  return round_state::send_and_wait_for_signed_blocks;
}

void pulse::main(void *quorumnet_state, cryptonote::core &core)
{
  cryptonote::Blockchain &blockchain          = core.get_blockchain_storage();
  gnodes::gnode_keys const &key = core.get_service_keys();

  //
  // NOTE: Early exit if too early
  //
  static uint64_t const hf16_height = cryptonote::HardFork::get_hardcoded_hard_fork_height(blockchain.nettype(), cryptonote::network_version_16_pulse);
  if (hf16_height == cryptonote::HardFork::INVALID_HF_VERSION_HEIGHT)
  {
    for (static bool once = true; once; once = !once)
      MERROR("Pulse: HF16 is not defined, pulse worker waiting");
    return;
  }

  if (uint64_t height = blockchain.get_current_blockchain_height(true /*lock*/); height < hf16_height)
  {
    for (static bool once = true; once; once = !once)
      MDEBUG("Pulse: Network at block " << height << " is not ready for Pulse until block " << hf16_height << ", waiting");
    return;
  }

  gnodes::gnode_list &node_list = core.get_gnode_list();
  for (auto last_state = round_state::null_state;
       last_state != context.state || last_state == round_state::null_state;)
  {
    last_state = context.state;

    switch (context.state)
    {
      case round_state::null_state:
        context.state = round_state::wait_for_next_block;
        break;

      case round_state::wait_for_next_block:
        context.state = wait_for_next_block(hf16_height, context, blockchain);
        break;

      case round_state::prepare_for_round:
        context.state = prepare_for_round(context, key, blockchain);
        break;

      case round_state::wait_for_round:
        context.state = wait_for_round(context, blockchain);
        break;

      case round_state::send_and_wait_for_handshakes:
        context.state = send_and_wait_for_handshakes(context, quorumnet_state, key);
        break;

      case round_state::send_handshake_bitsets:
        context.state = send_handshake_bitsets(context, quorumnet_state, key);
        break;

      case round_state::wait_for_handshake_bitsets:
        context.state = wait_for_handshake_bitsets(context, node_list, quorumnet_state, key);
        break;

      case round_state::wait_for_block_template:
        context.state = wait_for_block_template(context, node_list, quorumnet_state, key, blockchain);
        break;

      case round_state::send_block_template:
        context.state = send_block_template(context, quorumnet_state, key, blockchain);
        break;

      case round_state::send_and_wait_for_random_value_hashes:
        context.state = send_and_wait_for_random_value_hashes(context, node_list, quorumnet_state, key);
        break;

      case round_state::send_and_wait_for_random_value:
        context.state = send_and_wait_for_random_value(context, node_list, quorumnet_state, key);
        break;

      case round_state::send_and_wait_for_signed_blocks:
        context.state = send_and_wait_for_signed_blocks(context, node_list, quorumnet_state, key, core);
        break;
    }
  }
}

