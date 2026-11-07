#pragma once
// Custom block/allow rule domains: one normal form for the dashboard, the rule files
// and settings imports. Trims spaces, lower-cases, drops leading "*." / "." and
// trailing dots; then needs 3..253 characters of [a-z0-9-_.] with an inner dot and no
// empty label.

#include <cstddef>

namespace rules {

constexpr size_t kMaxRuleDomain = 253;

// Writes the normal form to out (NUL-terminated, cap >= kMaxRuleDomain + 1).
bool normaliseRuleDomain(const char* in, size_t len, char* out, size_t cap);

}  // namespace rules
