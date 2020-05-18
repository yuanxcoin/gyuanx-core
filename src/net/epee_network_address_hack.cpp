#include "net/net_utils_base.h"
#include "storages/portable_storage.h"
#include "tor_address.h"
#include "i2p_address.h"

// This unholy hack of defining epee implementation outside of epee is here because of Monero's lack
// of quality code review that allowed someone to add circular dependencies between src/net/ and
// epee/net_utils_base.cpp.  See the comment in epee/include/net/net_utils_base.h for the sordid
// details.
//
// TODO: epee needs to die.

namespace epee { namespace net_utils {

KV_SERIALIZE_MAP_CODE_BEGIN(network_address)
  static constexpr std::integral_constant<bool, is_store> is_store_{};

  std::uint8_t type = std::uint8_t(is_store ? this_ref.get_type_id() : address_type::invalid);
  if (!epee::serialization::selector<is_store>::serialize(type, stg, hparent_section, "type"))
    return false;

  switch (address_type(type))
  {
    case address_type::ipv4:
      return this_ref.template serialize_addr<ipv4_network_address>(is_store_, stg, hparent_section);
    case address_type::ipv6:
      return this_ref.template serialize_addr<ipv6_network_address>(is_store_, stg, hparent_section);
    case address_type::tor:
      return this_ref.template serialize_addr<net::tor_address>(is_store_, stg, hparent_section);
    case address_type::i2p:
      return this_ref.template serialize_addr<net::i2p_address>(is_store_, stg, hparent_section);
    default:
      MERROR("Unsupported network address type: " << (unsigned)type);
      return false;
  }
KV_SERIALIZE_MAP_CODE_END()

}}
