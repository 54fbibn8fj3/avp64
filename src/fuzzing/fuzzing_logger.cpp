#include "fuzzing/fuzzing_logger.hpp"

namespace fuzzing {
void FuzzLogger::write_log(testing::LogLevel level, std::string_view message) {
  constexpr char const *prefix = "TEST_INTERFACE: ";
  auto& log = ::mwr::select_logger();
  if (level == testing::LogLevel::Error) {
    log_error("%s%s", prefix, message.data());
  } else {
    log_info("%s%s", prefix, message.data());
  }
}

namespace {
inline std::string vformat(const char *fmt, va_list args) {
  std::vector<char> buf(1024);
  int               n = vsnprintf(buf.data(), buf.size(), fmt, args);
  if (n < 0) return {};
  if (size_t(n) < buf.size()) { return std::string(buf.data(), n); }
  // buffer was too small, resize and retry:
  buf.resize(n + 1);
  va_list args2;
  va_copy(args2, args);
  vsnprintf(buf.data(), buf.size(), fmt, args2);
  va_end(args2);
  return std::string(buf.data(), n);
}
}  // namespace

void log_info_message(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  std::string s = vformat(fmt, args);
  va_end(args);
  testing::get_global_logger()->write_log(testing::LogLevel::Info, s);
}

void log_error_message(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  std::string s = vformat(fmt, args);
  va_end(args);
  testing::get_global_logger()->write_log(testing::LogLevel::Error, s);
}
}  // namespace fuzzing
