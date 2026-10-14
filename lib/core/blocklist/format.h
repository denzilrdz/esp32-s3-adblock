#pragma once
// On-flash blocklist format v2 (ARCHITECTURE.md §6.1), all integers little-endian:
//
//   0   4   magic "ADBL"
//   4   1   version = 2
//   5   1   hash_bits = 48
//   6   1   prefix_bits = 16
//   7   1   flags = 0
//   8   4   entry count N
//   12  4   CRC-32 of everything after the header
//   16  8   build time (unix seconds)
//   24  8   reserved = 0
//   32      uint32 bucket_start[65537]  (monotonic, [0] == 0, [65536] == N)
//   ...     uint32 suffix[N]            (strictly ascending within each bucket)

#include <cstddef>
#include <cstdint>

#include "blocklist/hash.h"
#include "hal/file_system.h"

namespace blocklist {

constexpr size_t kHeaderSize = 32;
constexpr size_t kBucketTableEntries = kBucketCount + 1;
constexpr size_t kBucketTableBytes = kBucketTableEntries * 4;
constexpr uint8_t kFormatVersion = 2;

struct Header {
  uint32_t count = 0;
  uint32_t crc = 0;
  int64_t buildTime = 0;
};

inline size_t fileSizeFor(uint32_t count) { return kHeaderSize + kBucketTableBytes + size_t{4} * count; }

enum class FormatError {
  kNone,
  kTooShort,
  kBadMagic,
  kBadVersion,
  kBadParams,
  kSizeMismatch,
  kTooManyEntries,
  kTooFewEntries,
  kBadCrc,
  kBadBuckets,
  kUnsorted,
  kIoError,
};

const char* formatErrorName(FormatError e);

// Parses and checks the 32-byte header.
FormatError parseHeader(const uint8_t* data, size_t len, Header& out);

// Writes a header (used by tests and the dashboard upload path).
void writeHeader(uint8_t out[kHeaderSize], uint32_t count, uint32_t crc, int64_t buildTime);

struct Limits {
  uint32_t minEntries = 1000;
  uint32_t maxEntries = 1000000;
};

// Incremental validator for a download: checks the header, the total size and the
// CRC as bytes stream in, without buffering the file.
class StreamValidator {
 public:
  explicit StreamValidator(const Limits& limits) : limits_(limits) {}
  void feed(const uint8_t* data, size_t len);
  // Call after the last byte. Returns kNone if header, size and CRC are all correct.
  FormatError finish();
  const Header& header() const { return header_; }

 private:
  Limits limits_;
  uint8_t head_[kHeaderSize];
  size_t total_ = 0;
  uint32_t crc_ = 0;
  bool headerChecked_ = false;
  FormatError error_ = FormatError::kNone;
  Header header_;
};

// Full validation of a stored file: header, size, CRC, bucket monotonicity and
// suffix ordering. Streams the file with two sequential readers; constant memory.
FormatError validateFile(hal::IFileSystem& fs, const char* path, const Limits& limits, Header* out);

}  // namespace blocklist
