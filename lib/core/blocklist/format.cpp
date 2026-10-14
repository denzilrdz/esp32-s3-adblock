#include "blocklist/format.h"

#include <cstring>

#include "util/bytes.h"
#include "util/crc32.h"

namespace blocklist {

const char* formatErrorName(FormatError e) {
  switch (e) {
    case FormatError::kNone: return "ok";
    case FormatError::kTooShort: return "too short";
    case FormatError::kBadMagic: return "bad magic (not a v2 blocklist)";
    case FormatError::kBadVersion: return "unsupported version";
    case FormatError::kBadParams: return "unsupported hash parameters";
    case FormatError::kSizeMismatch: return "size does not match entry count";
    case FormatError::kTooManyEntries: return "too many entries";
    case FormatError::kTooFewEntries: return "too few entries";
    case FormatError::kBadCrc: return "crc mismatch";
    case FormatError::kBadBuckets: return "corrupt bucket table";
    case FormatError::kUnsorted: return "entries not sorted";
    case FormatError::kIoError: return "read error";
  }
  return "?";
}

FormatError parseHeader(const uint8_t* d, size_t len, Header& out) {
  if (len < kHeaderSize) return FormatError::kTooShort;
  if (memcmp(d, "ADBL", 4) != 0) return FormatError::kBadMagic;
  if (d[4] != kFormatVersion) return FormatError::kBadVersion;
  if (d[5] != kHashBits || d[6] != kPrefixBits || d[7] != 0) return FormatError::kBadParams;
  out.count = util::readU32Le(d + 8);
  out.crc = util::readU32Le(d + 12);
  out.buildTime = static_cast<int64_t>(util::readU64Le(d + 16));
  return FormatError::kNone;
}

void writeHeader(uint8_t out[kHeaderSize], uint32_t count, uint32_t crc, int64_t buildTime) {
  memset(out, 0, kHeaderSize);
  memcpy(out, "ADBL", 4);
  out[4] = kFormatVersion;
  out[5] = kHashBits;
  out[6] = kPrefixBits;
  util::writeU32Le(out + 8, count);
  util::writeU32Le(out + 12, crc);
  util::writeU64Le(out + 16, static_cast<uint64_t>(buildTime));
}

static FormatError checkLimits(const Header& h, const Limits& limits) {
  if (h.count > limits.maxEntries) return FormatError::kTooManyEntries;
  if (h.count < limits.minEntries) return FormatError::kTooFewEntries;
  return FormatError::kNone;
}

void StreamValidator::feed(const uint8_t* data, size_t len) {
  if (error_ != FormatError::kNone) return;
  size_t i = 0;
  while (total_ < kHeaderSize && i < len) head_[total_++] = data[i++];
  if (!headerChecked_ && total_ >= kHeaderSize) {
    headerChecked_ = true;
    error_ = parseHeader(head_, kHeaderSize, header_);
    if (error_ == FormatError::kNone) error_ = checkLimits(header_, limits_);
    if (error_ != FormatError::kNone) return;
  }
  if (i < len) {
    crc_ = util::crc32Update(crc_, data + i, len - i);
    total_ += len - i;
    // Reject an over-long stream early instead of filling the flash.
    if (headerChecked_ && total_ > fileSizeFor(header_.count)) error_ = FormatError::kSizeMismatch;
  }
}

FormatError StreamValidator::finish() {
  if (error_ != FormatError::kNone) return error_;
  if (!headerChecked_) return FormatError::kTooShort;
  if (total_ != fileSizeFor(header_.count)) return FormatError::kSizeMismatch;
  if (crc_ != header_.crc) return FormatError::kBadCrc;
  return FormatError::kNone;
}

namespace {

// Sequential little-endian uint32 reader with a small buffer.
class U32Reader {
 public:
  explicit U32Reader(hal::IFile& f) : f_(f) {}
  bool next(uint32_t& v) {
    if (pos_ + 4 > len_) {
      const size_t keep = len_ - pos_;
      memmove(buf_, buf_ + pos_, keep);
      len_ = keep + f_.read(buf_ + keep, sizeof(buf_) - keep);
      pos_ = 0;
      if (len_ < 4) return false;
    }
    v = util::readU32Le(buf_ + pos_);
    pos_ += 4;
    return true;
  }

 private:
  hal::IFile& f_;
  uint8_t buf_[512];
  size_t pos_ = 0;
  size_t len_ = 0;
};

}  // namespace

FormatError validateFile(hal::IFileSystem& fs, const char* path, const Limits& limits, Header* out) {
  auto f = fs.open(path, hal::FileMode::kRead);
  if (!f) return FormatError::kIoError;
  uint8_t head[kHeaderSize];
  if (f->read(head, kHeaderSize) != kHeaderSize) return FormatError::kTooShort;
  Header h;
  FormatError e = parseHeader(head, kHeaderSize, h);
  if (e != FormatError::kNone) return e;
  if ((e = checkLimits(h, limits)) != FormatError::kNone) return e;
  if (f->size() != fileSizeFor(h.count)) return FormatError::kSizeMismatch;

  // Pass 1: CRC over the payload.
  uint32_t crc = 0;
  uint8_t chunk[512];
  size_t n;
  while ((n = f->read(chunk, sizeof(chunk))) > 0) crc = util::crc32Update(crc, chunk, n);
  if (crc != h.crc) return FormatError::kBadCrc;

  // Pass 2: walk the bucket table and the suffixes side by side.
  auto buckets = fs.open(path, hal::FileMode::kRead);
  auto suffixes = fs.open(path, hal::FileMode::kRead);
  if (!buckets || !suffixes || !buckets->seek(kHeaderSize) ||
      !suffixes->seek(kHeaderSize + kBucketTableBytes))
    return FormatError::kIoError;
  U32Reader br(*buckets), sr(*suffixes);
  uint32_t start = 0;
  if (!br.next(start) || start != 0) return FormatError::kBadBuckets;
  for (uint32_t b = 0; b < kBucketCount; b++) {
    uint32_t end;
    if (!br.next(end) || end < start || end > h.count) return FormatError::kBadBuckets;
    bool first = true;
    uint32_t prev = 0;
    for (uint32_t i = start; i < end; i++) {
      uint32_t s;
      if (!sr.next(s)) return FormatError::kIoError;
      if (!first && s <= prev) return FormatError::kUnsorted;
      first = false;
      prev = s;
    }
    start = end;
  }
  if (start != h.count) return FormatError::kBadBuckets;
  if (out) *out = h;
  return FormatError::kNone;
}

}  // namespace blocklist
