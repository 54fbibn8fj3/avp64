#ifndef RECEIVER_HPP
#define RECEIVER_HPP

#include "vp_test/types.hpp"
#include "vp_test/pipe_comm_handler.hpp"
#include "vp_manager.hpp"
#include "init_config.hpp"

#include <fcntl.h>
#include <mqueue.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstdint>


namespace fuzzing {

// DO NOT replace these with #define and DO NOT use macros in the future
// Macros leak to files that include this header and might generate collisions
// Macros also ignores types & are impossible to debug
constexpr uint8_t MIN_COMM_SIZE = 21;

class Receiver {
 public:
  explicit Receiver(VPManager &vp_manager);
  ~Receiver();

  void init();

  void parse_args(int argc, const char *const *argv);

 private:
 /* ---- Dependencies ---- */
  VPManager &vp_manager;


  /* ---- Pipe Comm ---- */
  mwr::option<std::string> pipe_request_arg;
  mwr::option<std::string> pipe_response_arg;
  // Pointer to the communication object
  std::unique_ptr<testing::PipeCommHandler> pipe_comm;
  // Current active request and response.
  testing::Request  current_req;
  testing::Response current_res;

  bool init_comm_pipe(int fd_requests, int fd_response);


  /* ---- Receiving Loop */
  std::atomic<bool> stop_receiver = false;
  std::thread receiver_thread;

  bool start_receiver_in_thread();
  void receiver_loop();
  void receiver_loop_body();


  /* ---- Command helper functions ---- */
  void handle_request(testing::Request &req, testing::Response &res);

  testing::status handle_enable_mmio_tracking();

  testing::status handle_enable_code_coverage();

  testing::status handle_get_return_val(uint64_t &val);

  testing::status handle_get_code_coverage_shm();

  testing::status handle_init_shm(std::vector<uint8_t>& data);

  std::optional<InitConfig> parse_init_config(std::vector<uint8_t>& data);

};

}  // namespace fuzzing

#endif  // !RECEIVER_HPP
