#include "storages/portable_storage_to_json.h"

namespace epee {
  namespace serialization {
    namespace {
      struct array_entry_store_to_json_visitor: public boost::static_visitor<void>
      {
        std::ostream& m_strm;
        size_t m_indent;
        bool m_pretty; // If true: use 2-space indents, newlines, and spaces between elements.  If false, don't.
        array_entry_store_to_json_visitor(std::ostream& strm, size_t indent,
                                          bool pretty = true)
          : m_strm(strm), m_indent(indent), m_pretty(pretty)
        {}

        template<class t_type>
        void operator()(const array_entry_t<t_type>& a)
        {
          m_strm << '[';
          if (!a.m_array.empty())
          {
            for (auto it = a.m_array.begin(); it != a.m_array.end(); it++)
            {
              if (it != a.m_array.begin()) m_strm << ',';
              dump_as_json(m_strm, *it, m_indent, m_pretty);
            }
          }
          m_strm << "]";
        }
      };

      struct storage_entry_store_to_json_visitor: public boost::static_visitor<void>
      {
          std::ostream& m_strm;
        size_t m_indent;
        bool m_pretty;
        storage_entry_store_to_json_visitor(std::ostream& strm, size_t indent,
                                            bool pretty = true)
            : m_strm(strm), m_indent(indent), m_pretty(pretty)
        {}
        //section, array_entry
        template<class visited_type>
        void operator()(const visited_type& v)
        { 
          dump_as_json(m_strm, v, m_indent, m_pretty);
        }
      };
    }

    void dump_as_json(std::ostream& strm, const array_entry& ae, size_t indent, bool pretty)
    {
      array_entry_store_to_json_visitor aesv(strm, indent, pretty);
      boost::apply_visitor(aesv, ae);
    }

    void dump_as_json(std::ostream& strm, const storage_entry& se, size_t indent, bool pretty)
    {
      storage_entry_store_to_json_visitor sv(strm, indent, pretty);
      boost::apply_visitor(sv, se);
    }

    void dump_as_json(std::ostream& s, const std::string& v, size_t, bool)
    {
      s << '"';
      // JSON strings may only contain 0x20 and above, except for " and \\ which must be escaped.
      // For values below 0x20 we can use \u00XX escapes, except for the really common \n and \t (we
      // could also use \b, \f, \r, but it really isn't worth the bother.
      for (char c : v) {
        switch(c) {
          case '"':
          case '\\':
            s << '\\' << c;
            break;
          case '\n': s << "\\n"; break;
          case '\t': s << "\\t"; break;
          case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05: case 0x06: case 0x07:
          case 0x08: /*\t=0x09: \n=0x0a*/  case 0x0b: case 0x0c: case 0x0d: case 0x0e: case 0x0f:
          case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15: case 0x16: case 0x17:
          case 0x18: case 0x19: case 0x1a: case 0x1b: case 0x1c: case 0x1d: case 0x1e: case 0x1f:
            s << "\\u00" << (c >= 0x10 ? '1' : '0');
            c &= 0xf;
            s << (c < 0xa ? '0' + c : ('a' - 10) + c);
            break;
          default:
            s << c;
        }
      }
      s << '"';
    }


    void dump_as_json(std::ostream& strm, const section& sec, size_t indent, bool pretty)
    {
      strm << '{';
      if(sec.m_entries.empty())
        strm << '}';
      else
      {
        size_t local_indent = indent + 1;
        std::string line_sep(pretty * (1 + 2*local_indent), ' ');
        if (pretty) line_sep[0] = '\n';

        for (auto it = sec.m_entries.begin(); it != sec.m_entries.end(); ++it)
        {
          if (it != sec.m_entries.begin()) strm << ',';
          strm << line_sep;
          dump_as_json(strm, it->first, local_indent, pretty);
          strm << ':';
          if (pretty) strm << ' ';
          dump_as_json(strm, it->second, local_indent, pretty);
        }
        if (pretty)
          line_sep.resize(line_sep.size() - 2);
        strm << line_sep << '}';
      }
    }

  }
}
