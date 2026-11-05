#ifndef FUZZ_LOGGER_HPP
#define FUZZ_LOGGER_HPP

#include "vp_test/base_logger.hpp"
#include "vcml/logging/logger.h"

namespace fuzzing {

class FuzzLogger : public testing::BaseLogger {
 public:
  void write_log(testing::LogLevel level, std::string_view message) override;
};

void log_info_message(const char *fmt, ...);
void log_error_message(const char *fmt, ...);

}  // namespace fuzzing

#endif  // !USIMA_LOGGER_HPP
