#pragma once
#include <lokimq/string_view.h>
#include <iterator>

namespace tools {

/// Returns true if the first string is equal to the second string, compared case-insensitively.
inline bool string_iequal(lokimq::string_view s1, lokimq::string_view s2) {
  return std::equal(s1.begin(), s1.end(), s2.begin(), s2.end(), [](char a, char b) {
      return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); });
}

/// Returns true if the first string matches any of the given strings case-insensitively.  Arguments
/// must be string literals, std::string, or lokimq::string_views
#ifdef __cpp_fold_expressions
template <typename S1, typename... S>
bool string_iequal_any(const S1& s1, const S&... s) {
  return (string_iequal(s1, s) || ...);
}
#else
template <typename S1>
constexpr bool string_iequal_any(const S1& s1) {
  return false;
}
template <typename S1, typename S2, typename... S>
bool string_iequal_any(const S1& s1, const S2& s2, const S&... s) {
  return string_iequal(s1, s2) || string_iequal_any(s1, s...);
}
#endif

}
