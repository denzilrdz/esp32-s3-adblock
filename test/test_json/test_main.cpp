// Tests for lib/core/util/json (settings-file reader/writer) and the calendar helpers
// the reboot schedule uses (weekday, addDays, parseHhMm).

#include <unity.h>

#include <cstring>
#include <string>

#include "util/civil_time.h"
#include "util/json.h"

using util::JsonReader;
using util::JsonWriter;

void setUp() {}
void tearDown() {}

static JsonReader reader(const char* s) {
  return JsonReader(s, strlen(s));
}

// ---- writer ---------------------------------------------------------------------

static void test_writer_pretty_prints_and_escapes() {
  std::string out;
  JsonWriter w(out);
  w.beginObject();
  w.key("s");
  w.value("a\"b\\c\n\t\x01/é");
  w.key("n");
  w.value(static_cast<uint32_t>(4294967295u));
  w.key("b");
  w.value(false);
  w.key("empty");
  w.beginArray();
  w.endArray();
  w.key("list");
  w.beginArray();
  w.value("x");
  w.value(true);
  w.endArray();
  w.endObject();
  TEST_ASSERT_EQUAL_STRING(
      "{\n  \"s\": \"a\\\"b\\\\c\\n\\t\\u0001/é\",\n  \"n\": 4294967295,\n  \"b\": false,\n"
      "  \"empty\": [],\n  \"list\": [\n    \"x\",\n    true\n  ]\n}",
      out.c_str());
}

static void test_writer_output_reads_back() {
  std::string out;
  JsonWriter w(out);
  w.beginObject();
  w.key("k");
  w.value("quote \" and \\ and \x1f\r");
  w.endObject();
  JsonReader r(out.data(), out.size());
  char key[8], val[64];
  TEST_ASSERT_TRUE(r.beginObject());
  TEST_ASSERT_TRUE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_TRUE(r.readString(val, sizeof(val)));
  TEST_ASSERT_EQUAL_STRING("quote \" and \\ and \x1f\r", val);
  TEST_ASSERT_FALSE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_TRUE(r.atEnd());
}

// ---- reader ---------------------------------------------------------------------

static void test_reader_walks_objects_and_arrays() {
  JsonReader r = reader(" { \"a\" : [1, 2 ,3], \"b\": {\"c\": true}, \"d\": \"x\" } \n");
  char key[8], s[8];
  uint32_t n = 0, sum = 0;
  bool b = false;
  TEST_ASSERT_TRUE(r.beginObject());
  TEST_ASSERT_TRUE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_EQUAL_STRING("a", key);
  TEST_ASSERT_TRUE(r.beginArray());
  while (r.nextElement()) {
    TEST_ASSERT_TRUE(r.readU32(n));
    sum += n;
  }
  TEST_ASSERT_TRUE(r.ok());
  TEST_ASSERT_EQUAL(6u, sum);
  TEST_ASSERT_TRUE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_TRUE(r.beginObject());
  TEST_ASSERT_TRUE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_TRUE(r.readBool(b));
  TEST_ASSERT_TRUE(b);
  TEST_ASSERT_FALSE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_TRUE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_EQUAL(static_cast<int>(JsonReader::Type::kString), static_cast<int>(r.peek()));
  TEST_ASSERT_TRUE(r.readString(s, sizeof(s)));
  TEST_ASSERT_FALSE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_TRUE(r.ok());
  TEST_ASSERT_TRUE(r.atEnd());
}

static void test_reader_empty_containers() {
  JsonReader r = reader("{\"a\":[],\"b\":{}}");
  char key[4];
  TEST_ASSERT_TRUE(r.beginObject());
  TEST_ASSERT_TRUE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_TRUE(r.beginArray());
  TEST_ASSERT_FALSE(r.nextElement());
  TEST_ASSERT_TRUE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_TRUE(r.beginObject());
  TEST_ASSERT_FALSE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_FALSE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_TRUE(r.atEnd());
}

static void test_reader_decodes_escapes_to_utf8() {
  JsonReader r = reader("\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041\\u00E9\\u20ac\\ud83d\\ude00\"");
  char s[32];
  size_t n = 0;
  TEST_ASSERT_TRUE(r.readString(s, sizeof(s), &n));
  TEST_ASSERT_EQUAL_STRING("\"\\/\b\f\n\r\tA\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80", s);
  TEST_ASSERT_EQUAL(18u, n);
}

static void test_reader_skips_any_value() {
  JsonReader r = reader("{\"x\":[{\"y\":[null,-1.5e+3,0,\"s\",false,{}]}],\"z\":7}");
  char key[4];
  uint32_t z = 0;
  TEST_ASSERT_TRUE(r.beginObject());
  TEST_ASSERT_TRUE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_TRUE(r.skipValue());
  TEST_ASSERT_TRUE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_EQUAL_STRING("z", key);
  TEST_ASSERT_TRUE(r.readU32(z));
  TEST_ASSERT_EQUAL(7u, z);
  TEST_ASSERT_FALSE(r.nextKey(key, sizeof(key)));
  TEST_ASSERT_TRUE(r.atEnd());
}

// Every malformed document fails (never crashes, never reads past the end).
static void test_reader_rejects_malformed_documents() {
  const char* bad[] = {
      "",                    // nothing
      "{",                   // unclosed
      "{\"a\":1,}",          // trailing comma
      "[1,]",                // trailing comma
      "[,1]",                // leading comma
      "{\"a\" 1}",           // missing colon
      "{a:1}",               // unquoted key
      "{'a':1}",             // single quotes
      "[1 2]",               // missing comma
      "\"abc",               // unterminated string
      "\"a\\x\"",            // bad escape
      "\"a\\u12\"",          // short \u
      "\"a\\u12G4\"",        // bad hex
      "\"\\ud83d\"",         // lone high surrogate
      "\"\\ude00\"",         // lone low surrogate
      "\"\\ud83d\\u0041\"",  // high surrogate + non-surrogate
      "\"a\\u0000b\"",       // NUL
      "\"tab\there\"",       // raw control character
      "tru",                 // truncated literal
      "nul",                 // truncated literal
      "-",                   // bad number
      "1.",                  // bad number
      "1e",                  // bad number
      ".5",                  // bad number
      "{} {}",               // trailing data
      "{}x",                 // trailing garbage
      "]",                   // stray close
  };
  for (const char* doc : bad) {
    JsonReader r(doc, strlen(doc));
    const bool ok = r.skipValue() && r.atEnd();
    TEST_ASSERT_FALSE_MESSAGE(ok, doc);
    TEST_ASSERT_FALSE_MESSAGE(r.ok(), doc);
    TEST_ASSERT_TRUE(strlen(r.error()) > 0);
    TEST_ASSERT_TRUE(r.errorOffset() <= strlen(doc));
  }
}

static void test_reader_errors_are_sticky() {
  JsonReader r = reader("[\"a\", 1]");
  char s[4];
  uint32_t n;
  TEST_ASSERT_TRUE(r.beginArray());
  TEST_ASSERT_TRUE(r.nextElement());
  TEST_ASSERT_FALSE(r.readU32(n));  // a string, not a number
  TEST_ASSERT_FALSE(r.ok());
  TEST_ASSERT_EQUAL_STRING("expected a whole number", r.error());
  TEST_ASSERT_FALSE(r.readString(s, sizeof(s)));  // still failing
  TEST_ASSERT_FALSE(r.nextElement());
  TEST_ASSERT_EQUAL(static_cast<int>(JsonReader::Type::kNone), static_cast<int>(r.peek()));
  TEST_ASSERT_EQUAL_STRING("expected a whole number", r.error());
}

static void test_reader_numbers() {
  uint32_t n = 0;
  JsonReader a = reader("4294967295");
  TEST_ASSERT_TRUE(a.readU32(n));
  TEST_ASSERT_EQUAL_UINT32(4294967295u, n);
  const char* bad[] = {"4294967296", "-1", "1.0", "1e3", "01", "99999999999999999999"};
  for (const char* doc : bad) {
    JsonReader r(doc, strlen(doc));
    TEST_ASSERT_FALSE_MESSAGE(r.readU32(n), doc);
  }
  JsonReader z = reader("0");
  TEST_ASSERT_TRUE(z.readU32(n));
  TEST_ASSERT_EQUAL(0u, n);
}

static void test_reader_string_longer_than_buffer_is_an_error() {
  JsonReader r = reader("\"abcdef\"");
  char s[6];  // room for 5 + NUL
  TEST_ASSERT_FALSE(r.readString(s, sizeof(s)));
  TEST_ASSERT_EQUAL_STRING("string too long", r.error());
  JsonReader fits = reader("\"abcde\"");
  TEST_ASSERT_TRUE(fits.readString(s, sizeof(s)));
  TEST_ASSERT_EQUAL_STRING("abcde", s);
  char key[3];
  JsonReader k = reader("{\"long\":1}");
  TEST_ASSERT_TRUE(k.beginObject());
  TEST_ASSERT_FALSE(k.nextKey(key, sizeof(key)));
  TEST_ASSERT_FALSE(k.ok());
}

static void test_reader_limits_nesting_depth() {
  std::string deep(JsonReader::kMaxDepth, '[');
  deep += std::string(JsonReader::kMaxDepth, ']');
  JsonReader ok(deep.data(), deep.size());
  TEST_ASSERT_TRUE(ok.skipValue());
  TEST_ASSERT_TRUE(ok.atEnd());
  std::string tooDeep(JsonReader::kMaxDepth + 1, '[');
  tooDeep += std::string(JsonReader::kMaxDepth + 1, ']');
  JsonReader no(tooDeep.data(), tooDeep.size());
  TEST_ASSERT_FALSE(no.skipValue());
  TEST_ASSERT_EQUAL_STRING("nesting too deep", no.error());
  std::string bomb(100000, '[');  // no stack overflow from a hostile file
  JsonReader b(bomb.data(), bomb.size());
  TEST_ASSERT_FALSE(b.skipValue());
}

static void test_reader_misuse_fails_cleanly() {
  JsonReader r = reader("{\"a\":1}");
  char key[4];
  TEST_ASSERT_FALSE(r.nextElement());  // not in an array
  TEST_ASSERT_FALSE(r.ok());
  JsonReader n(nullptr, 0);
  TEST_ASSERT_FALSE(n.beginObject());
  TEST_ASSERT_FALSE(n.nextKey(key, sizeof(key)));
}

// ---- calendar helpers -----------------------------------------------------------

static util::CivilTime date(int y, int m, int d) {
  util::CivilTime t;
  t.year = y;
  t.month = m;
  t.day = d;
  return t;
}

static void test_weekday_known_dates() {
  TEST_ASSERT_EQUAL(4, util::weekday(date(1970, 1, 1)));    // Thursday
  TEST_ASSERT_EQUAL(3, util::weekday(date(1969, 12, 31)));  // before the epoch
  TEST_ASSERT_EQUAL(0, util::weekday(date(1969, 12, 28)));
  TEST_ASSERT_EQUAL(6, util::weekday(date(2026, 11, 7)));  // Saturday
  TEST_ASSERT_EQUAL(0, util::weekday(date(2026, 11, 8)));  // Sunday
  TEST_ASSERT_EQUAL(1, util::weekday(date(2000, 1, 3)));   // Monday
  TEST_ASSERT_EQUAL(2, util::weekday(date(2000, 2, 29)));  // leap day, Tuesday
  TEST_ASSERT_EQUAL(5, util::weekday(date(2100, 1, 1)));   // Friday
}

static void test_add_days_crosses_months_years_and_leap_days() {
  util::CivilTime t = date(2028, 2, 28);
  t.hour = 23;
  t.minute = 59;
  util::CivilTime u = util::addDays(t, 1);
  TEST_ASSERT_EQUAL(20280229u, u.dateKey());
  TEST_ASSERT_EQUAL(23, u.hour);
  TEST_ASSERT_EQUAL(59, u.minute);
  TEST_ASSERT_EQUAL(20280301u, util::addDays(t, 2).dateKey());
  TEST_ASSERT_EQUAL(20261231u, util::addDays(date(2027, 1, 1), -1).dateKey());
  TEST_ASSERT_EQUAL(20270101u, util::addDays(date(2026, 12, 31), 1).dateKey());
  TEST_ASSERT_EQUAL(20261107u, util::addDays(date(2026, 11, 7), 0).dateKey());
  TEST_ASSERT_EQUAL(20261114u, util::addDays(date(2026, 11, 7), 7).dateKey());
}

static void test_parse_hhmm_is_strict() {
  uint8_t h = 99, m = 99;
  TEST_ASSERT_TRUE(util::parseHhMm("00:00", h, m));
  TEST_ASSERT_EQUAL(0, h);
  TEST_ASSERT_EQUAL(0, m);
  TEST_ASSERT_TRUE(util::parseHhMm("23:59", h, m));
  TEST_ASSERT_EQUAL(23, h);
  TEST_ASSERT_EQUAL(59, m);
  TEST_ASSERT_TRUE(util::parseHhMm("4:05", h, m));
  TEST_ASSERT_EQUAL(4, h);
  TEST_ASSERT_EQUAL(5, m);
  const char* bad[] = {"24:00", "12:60", "12:5", "12:005", ":30", "123:00", "-1:00", " 4:00",
                       "4:00 ", "4.00",  "4:0a", "",       "12",  "1:2:3",  "+4:00"};
  for (const char* s : bad) {
    h = m = 77;
    TEST_ASSERT_FALSE_MESSAGE(util::parseHhMm(s, h, m), s);
    TEST_ASSERT_EQUAL(77, h);  // untouched on failure
  }
  TEST_ASSERT_FALSE(util::parseHhMm(nullptr, h, m));
}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_writer_pretty_prints_and_escapes);
  RUN_TEST(test_writer_output_reads_back);
  RUN_TEST(test_reader_walks_objects_and_arrays);
  RUN_TEST(test_reader_empty_containers);
  RUN_TEST(test_reader_decodes_escapes_to_utf8);
  RUN_TEST(test_reader_skips_any_value);
  RUN_TEST(test_reader_rejects_malformed_documents);
  RUN_TEST(test_reader_errors_are_sticky);
  RUN_TEST(test_reader_numbers);
  RUN_TEST(test_reader_string_longer_than_buffer_is_an_error);
  RUN_TEST(test_reader_limits_nesting_depth);
  RUN_TEST(test_reader_misuse_fails_cleanly);
  RUN_TEST(test_weekday_known_dates);
  RUN_TEST(test_add_days_crosses_months_years_and_leap_days);
  RUN_TEST(test_parse_hhmm_is_strict);
  return UNITY_END();
}
