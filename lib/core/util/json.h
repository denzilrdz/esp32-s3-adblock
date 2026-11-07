#pragma once
// Minimal JSON for the settings file (config/backup.h): a writer that appends to a
// std::string and a strict pull reader over a caller's buffer. Not for the DNS hot
// path (the writer allocates).
//
// Reader: RFC 8259 syntax, UTF-8 passed through, \uXXXX escapes (with surrogate pairs)
// decoded to UTF-8. Errors are sticky: after the first one every call fails and
// error() says what and where. Limits keep a hostile file cheap: nesting depth
// kMaxDepth, numbers as unsigned integers only (what the settings file uses), strings
// longer than the caller's buffer are an error, not truncated.

#include <cstddef>
#include <cstdint>
#include <string>

namespace util {

class JsonWriter {
 public:
  explicit JsonWriter(std::string& out) : out_(out) {}

  void beginObject();
  void endObject();
  void beginArray();
  void endArray();
  void key(const char* k);  // inside an object, before each value
  void value(const char* s);
  void value(const char* s, size_t len);
  void value(bool b);
  void value(uint32_t n);

 private:
  void separator();  // comma + newline/indent between items
  void newline();
  void quoted(const char* s, size_t len);

  std::string& out_;
  int depth_ = 0;
  bool first_ = true;      // no item yet in the current container
  bool afterKey_ = false;  // the next value follows "key": on the same line
};

class JsonReader {
 public:
  enum class Type { kNone, kObject, kArray, kString, kNumber, kBool, kNull };
  static constexpr int kMaxDepth = 16;

  JsonReader(const char* data, size_t len);

  Type peek();  // type of the next value (kNone at the end or after an error)

  bool beginObject();
  // Next key of the current object into key (NUL-terminated). False at '}' (consumed)
  // or on an error; check ok() to tell them apart.
  bool nextKey(char* key, size_t cap);
  bool beginArray();
  // True if another element follows; false at ']' (consumed) or on an error.
  bool nextElement();

  bool readString(char* out, size_t cap, size_t* len = nullptr);
  bool readBool(bool& out);
  bool readU32(uint32_t& out);
  bool skipValue();  // any value, nested containers included
  bool atEnd();      // only whitespace left (call after the top-level value)

  bool ok() const { return !err_; }
  const char* error() const { return err_ ? err_ : ""; }
  size_t errorOffset() const { return errPos_; }

 private:
  struct Frame {
    bool object;
    bool first;
  };
  void ws();
  bool fail(const char* why);
  bool expect(char c);
  bool literal(const char* word);
  bool parseString(char* out, size_t cap, size_t* len);  // out may be null: skip
  bool skip();                                           // recursion is bounded by kMaxDepth (push)
  bool push(bool object);
  bool continueContainer(bool object);  // shared by nextKey/nextElement

  const char* p_;
  const char* end_;
  const char* start_;
  const char* err_ = nullptr;
  size_t errPos_ = 0;
  Frame stack_[kMaxDepth];
  int depth_ = 0;
};

}  // namespace util
