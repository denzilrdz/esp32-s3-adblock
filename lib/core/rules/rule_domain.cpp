#include "rules/rule_domain.h"

#include <cstring>

namespace rules {

bool normaliseRuleDomain(const char* in, size_t len, char* out, size_t cap) {
  if (!in || !out || cap <= kMaxRuleDomain) return false;
  auto space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
  while (len && space(*in)) in++, len--;
  while (len && space(in[len - 1])) len--;
  while (len) {
    if (len >= 2 && in[0] == '*' && in[1] == '.')
      in += 2, len -= 2;
    else if (in[0] == '.')
      in++, len--;
    else
      break;
  }
  while (len && in[len - 1] == '.') len--;
  if (len < 3 || len > kMaxRuleDomain) return false;
  bool dot = false;
  for (size_t i = 0; i < len; i++) {
    char c = in[i];
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_')) return false;
    if (c == '.') {
      if (i + 1 < len && in[i + 1] == '.') return false;
      dot = true;
    }
    out[i] = c;
  }
  out[len] = 0;
  return dot;
}

}  // namespace rules
