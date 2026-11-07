#include "util/json.h"

#include <cstdio>
#include <cstring>

namespace util {

// ---- writer -----------------------------------------------------------------------

void JsonWriter::newline() {
  out_ += '\n';
  out_.append(static_cast<size_t>(depth_) * 2, ' ');
}

void JsonWriter::separator() {
  if (afterKey_) {
    afterKey_ = false;
    return;
  }
  if (depth_ > 0) {
    if (!first_) out_ += ',';
    newline();
  }
  first_ = false;
}

void JsonWriter::beginObject() {
  separator();
  out_ += '{';
  depth_++;
  first_ = true;
}

void JsonWriter::endObject() {
  depth_--;
  if (!first_) newline();
  out_ += '}';
  first_ = false;
}

void JsonWriter::beginArray() {
  separator();
  out_ += '[';
  depth_++;
  first_ = true;
}

void JsonWriter::endArray() {
  depth_--;
  if (!first_) newline();
  out_ += ']';
  first_ = false;
}

void JsonWriter::key(const char* k) {
  separator();
  quoted(k, strlen(k));
  out_ += ": ";
  afterKey_ = true;
}

void JsonWriter::quoted(const char* s, size_t len) {
  out_ += '"';
  for (size_t i = 0; i < len; i++) {
    const char c = s[i];
    switch (c) {
      case '"': out_ += "\\\""; break;
      case '\\': out_ += "\\\\"; break;
      case '\n': out_ += "\\n"; break;
      case '\r': out_ += "\\r"; break;
      case '\t': out_ += "\\t"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
          out_ += buf;
        } else {
          out_ += c;
        }
    }
  }
  out_ += '"';
}

void JsonWriter::value(const char* s) {
  value(s ? s : "", s ? strlen(s) : 0);
}

void JsonWriter::value(const char* s, size_t len) {
  separator();
  quoted(s, len);
}

void JsonWriter::value(bool b) {
  separator();
  out_ += b ? "true" : "false";
}

void JsonWriter::value(uint32_t n) {
  separator();
  char buf[12];
  snprintf(buf, sizeof(buf), "%lu", static_cast<unsigned long>(n));
  out_ += buf;
}

// ---- reader -----------------------------------------------------------------------

JsonReader::JsonReader(const char* data, size_t len) : p_(data), end_(data + len), start_(data) {
  if (!data) {
    p_ = end_ = start_ = "";
  }
}

void JsonReader::ws() {
  while (p_ < end_ && (*p_ == ' ' || *p_ == '\t' || *p_ == '\n' || *p_ == '\r')) p_++;
}

bool JsonReader::fail(const char* why) {
  if (!err_) {
    err_ = why;
    errPos_ = static_cast<size_t>(p_ - start_);
  }
  return false;
}

bool JsonReader::expect(char c) {
  ws();
  if (p_ >= end_) return fail("unexpected end of file");
  if (*p_ != c) return fail(c == ':' ? "expected ':'" : c == ',' ? "expected ','" : "unexpected character");
  p_++;
  return true;
}

bool JsonReader::literal(const char* word) {
  const size_t n = strlen(word);
  if (static_cast<size_t>(end_ - p_) < n || memcmp(p_, word, n) != 0) return fail("invalid literal");
  p_ += n;
  return true;
}

JsonReader::Type JsonReader::peek() {
  if (err_) return Type::kNone;
  ws();
  if (p_ >= end_) return Type::kNone;
  switch (*p_) {
    case '{': return Type::kObject;
    case '[': return Type::kArray;
    case '"': return Type::kString;
    case 't':
    case 'f': return Type::kBool;
    case 'n': return Type::kNull;
    default: return (*p_ == '-' || (*p_ >= '0' && *p_ <= '9')) ? Type::kNumber : Type::kNone;
  }
}

bool JsonReader::push(bool object) {
  if (depth_ >= kMaxDepth) return fail("nesting too deep");
  stack_[depth_++] = Frame{object, true};
  return true;
}

bool JsonReader::beginObject() {
  if (err_) return false;
  if (peek() != Type::kObject) return fail("expected an object");
  p_++;
  return push(true);
}

bool JsonReader::beginArray() {
  if (err_) return false;
  if (peek() != Type::kArray) return fail("expected an array");
  p_++;
  return push(false);
}

bool JsonReader::continueContainer(bool object) {
  if (err_) return false;
  if (depth_ == 0 || stack_[depth_ - 1].object != object) return fail("misplaced read");
  ws();
  if (p_ >= end_) return fail("unexpected end of file");
  if (*p_ == (object ? '}' : ']')) {
    p_++;
    depth_--;
    return false;
  }
  Frame& f = stack_[depth_ - 1];
  if (!f.first && !expect(',')) return false;
  f.first = false;
  ws();
  return true;
}

bool JsonReader::nextKey(char* key, size_t cap) {
  if (!continueContainer(true)) return false;
  if (p_ >= end_ || *p_ != '"') return fail("expected a key");
  return parseString(key, cap, nullptr) && expect(':');
}

bool JsonReader::nextElement() {
  return continueContainer(false);
}

bool JsonReader::readString(char* out, size_t cap, size_t* len) {
  if (err_) return false;
  if (peek() != Type::kString) return fail("expected a string");
  return parseString(out, cap, len);
}

bool JsonReader::parseString(char* out, size_t cap, size_t* len) {
  p_++;  // opening quote
  size_t n = 0;
  auto put = [&](uint32_t cp) {
    char enc[4];
    size_t k;
    if (cp < 0x80) {
      enc[0] = static_cast<char>(cp);
      k = 1;
    } else if (cp < 0x800) {
      enc[0] = static_cast<char>(0xC0 | (cp >> 6));
      enc[1] = static_cast<char>(0x80 | (cp & 0x3F));
      k = 2;
    } else if (cp < 0x10000) {
      enc[0] = static_cast<char>(0xE0 | (cp >> 12));
      enc[1] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      enc[2] = static_cast<char>(0x80 | (cp & 0x3F));
      k = 3;
    } else {
      enc[0] = static_cast<char>(0xF0 | (cp >> 18));
      enc[1] = static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
      enc[2] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
      enc[3] = static_cast<char>(0x80 | (cp & 0x3F));
      k = 4;
    }
    if (out) {
      if (n + k >= cap) return fail("string too long");
      memcpy(out + n, enc, k);
    }
    n += k;
    return true;
  };
  auto hex4 = [&](uint32_t& v) {
    if (end_ - p_ < 4) return fail("bad \\u escape");
    v = 0;
    for (int i = 0; i < 4; i++) {
      const char c = *p_++;
      v <<= 4;
      if (c >= '0' && c <= '9')
        v |= static_cast<uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f')
        v |= static_cast<uint32_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F')
        v |= static_cast<uint32_t>(c - 'A' + 10);
      else
        return fail("bad \\u escape");
    }
    return true;
  };
  while (true) {
    if (p_ >= end_) return fail("unterminated string");
    const unsigned char c = static_cast<unsigned char>(*p_++);
    if (c == '"') break;
    if (c < 0x20) return fail("control character in string");
    if (c != '\\') {
      if (!put(c)) return false;
      continue;
    }
    if (p_ >= end_) return fail("unterminated string");
    const char e = *p_++;
    uint32_t cp = 0;
    switch (e) {
      case '"': cp = '"'; break;
      case '\\': cp = '\\'; break;
      case '/': cp = '/'; break;
      case 'b': cp = '\b'; break;
      case 'f': cp = '\f'; break;
      case 'n': cp = '\n'; break;
      case 'r': cp = '\r'; break;
      case 't': cp = '\t'; break;
      case 'u': {
        if (!hex4(cp)) return false;
        if (cp >= 0xDC00 && cp <= 0xDFFF) return fail("lone surrogate in \\u escape");
        if (cp >= 0xD800 && cp <= 0xDBFF) {
          uint32_t lo = 0;
          if (end_ - p_ < 2 || p_[0] != '\\' || p_[1] != 'u') return fail("lone surrogate in \\u escape");
          p_ += 2;
          if (!hex4(lo)) return false;
          if (lo < 0xDC00 || lo > 0xDFFF) return fail("lone surrogate in \\u escape");
          cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
        }
        if (cp == 0) return fail("NUL in string");
        break;
      }
      default: return fail("bad escape in string");
    }
    if (!put(cp)) return false;
  }
  if (out) out[n] = 0;
  if (len) *len = n;
  return true;
}

bool JsonReader::readBool(bool& out) {
  if (err_) return false;
  if (peek() != Type::kBool) return fail("expected true or false");
  if (*p_ == 't') {
    if (!literal("true")) return false;
    out = true;
  } else {
    if (!literal("false")) return false;
    out = false;
  }
  return true;
}

bool JsonReader::readU32(uint32_t& out) {
  if (err_) return false;
  if (peek() != Type::kNumber || *p_ == '-') return fail("expected a whole number");
  const char* s = p_;
  uint64_t v = 0;
  while (p_ < end_ && *p_ >= '0' && *p_ <= '9') {
    v = v * 10 + static_cast<uint64_t>(*p_++ - '0');
    if (v > 0xFFFFFFFFull) return fail("number too large");
  }
  if (p_ - s > 1 && *s == '0') return fail("leading zero in number");
  if (p_ < end_ && (*p_ == '.' || *p_ == 'e' || *p_ == 'E')) return fail("expected a whole number");
  out = static_cast<uint32_t>(v);
  return true;
}

bool JsonReader::skipValue() {
  return skip();
}

bool JsonReader::skip() {
  if (err_) return false;
  switch (peek()) {
    case Type::kObject: {
      beginObject();
      while (nextKey(nullptr, 0))
        if (!skip()) return false;
      return ok();
    }
    case Type::kArray: {
      beginArray();
      while (nextElement())
        if (!skip()) return false;
      return ok();
    }
    case Type::kString: return parseString(nullptr, 0, nullptr);
    case Type::kBool: {
      bool b;
      return readBool(b);
    }
    case Type::kNull: return literal("null");
    case Type::kNumber: {
      // -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?
      auto digits = [&]() {
        const char* s = p_;
        while (p_ < end_ && *p_ >= '0' && *p_ <= '9') p_++;
        return p_ > s;
      };
      if (*p_ == '-') p_++;
      if (p_ < end_ && *p_ == '0')
        p_++;
      else if (!digits())
        return fail("bad number");
      if (p_ < end_ && *p_ == '.') {
        p_++;
        if (!digits()) return fail("bad number");
      }
      if (p_ < end_ && (*p_ == 'e' || *p_ == 'E')) {
        p_++;
        if (p_ < end_ && (*p_ == '+' || *p_ == '-')) p_++;
        if (!digits()) return fail("bad number");
      }
      return true;
    }
    case Type::kNone: break;
  }
  return fail(p_ >= end_ ? "unexpected end of file" : "unexpected character");
}

bool JsonReader::atEnd() {
  if (err_) return false;
  ws();
  if (depth_ != 0) return fail("unclosed object or array");
  if (p_ != end_) return fail("unexpected data after the end");
  return true;
}

}  // namespace util
