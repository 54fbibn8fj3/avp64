#include "fuzzing/receiver.hpp"
#include <vp_test/conversion.hpp>
#include "fuzzing/fuzzing_logger.hpp"

namespace fuzzing {

Receiver::Receiver(VPManager &vp_manager)
    : vp_manager(vp_manager),
      pipe_request_arg("--test-receiver-pipe-request",
                       "File descriptor of the pipe where requests are "
                       "read from. Required for interface 1."),
      pipe_response_arg("--test-receiver-pipe-response",
                        "File descriptor of the pipe where responses are "
                        "send to. Required for interface 1.") {
}


void Receiver::parse_args(int argc, const char *const *argv) {
  pipe_request_arg.parse(argc, argv);
  pipe_response_arg.parse(argc, argv);
}


void Receiver::init() {
  log_info_message("Initializing Target Manager");

  if (!pipe_request_arg.has_value() || !pipe_response_arg.has_value()) {
    log_error_message(
        "In order to use pipes for communication, "
        "--test-receiver-pipe-request and "
        "--test-receiver-pipe-response must be set!");
    exit(1);
  }

  int pipe_request_fd = -1;
  int pipe_response_fd = -1;

  try {
    pipe_request_fd = std::stoi(pipe_request_arg.value());
    pipe_response_fd = std::stoi(pipe_response_arg.value());
  } catch (std::exception &e) {
    log_error_message(
        "specified pipe FDs (--test-receiver-pipe-request or "
        "--test-receiver-pipe-response) are not valid numbers.");
    exit(1);
  }

  log_info_message("Pipe FDs: %d (req) and %d (res).", pipe_request_fd,
                   pipe_response_fd);

  /* This sends the ready message to the harness */
  if (!init_comm_pipe(pipe_request_fd, pipe_response_fd)) {
    log_error_message("Error starting pipes");
    exit(1);
  }

  start_receiver_in_thread();
}


bool Receiver::init_comm_pipe(int fd_requests, int fd_response) {
    pipe_comm = std::make_unique<testing::PipeCommHandler>(fd_requests, fd_response);
    if (!pipe_comm->start()) { return false; }

    return true;
}


/* Starts the receiver loop inside a new thread. */
bool Receiver::start_receiver_in_thread() {
  log_info_message("Receiver thread starting.");

  receiver_thread = std::thread([this] { this->receiver_loop(); });

  return true;
}

void Receiver::receiver_loop() {
  while (!stop_receiver) {
    receiver_loop_body();
  }
}

void Receiver::receiver_loop_body() {

    if (!pipe_comm->receive_request()) { 
        std::this_thread::yield(); // Prevent this thread from blocking the others
        return; 
    }

    current_req = pipe_comm->get_request();
    //testing::Response current_res;

    log_info_message("Successfully received request with command: ");
    log_info_message(testing::command_string[current_req.request_command].c_str());

    handle_request(current_req, current_res);

    if (pipe_comm->send_response(current_res)) {
        log_info_message("Successfully sent response: ");
        log_info_message(testing::status_string[current_res.response_status].c_str());
    } 
    else 
    log_error_message("Could not send response");

    // Clearing response data. Request data is cleared by m_communication.
    if (!current_res.data.empty()) { current_res.data.clear(); }
}


std::optional<InitConfig> Receiver::parse_init_config(std::vector<uint8_t>& data)
{
  // Content:
  // (4 Bytes) Shared memory ID (input) +
  // (4 Bytes) SHM offset (input) +
  // (4 Bytes) Shared memory ID (coverage) +
  // (4 Bytes) SHM offset (coverage) +
  // (1 Bytes) Start breakpoint name length +
  // (1 Bytes) End breakpoint name length +
  // (1 Bytes) Return register name length +
  // (1 Bytes) Run mode (persistent/normal) +
  // (1 Bytes) Error symbol name length
  // (? Bytes) Start brkp + End brkp + Ret reg + Send data brkp + Error
  // symb
  using namespace testing::conversion;

  BufferReader reader(data);

  InitConfig init_cfg{}; // {} important for value initialization!

  if(!reader.read_int32(init_cfg.input_shm_id)) return std::nullopt;
  if(!reader.read_int32(init_cfg.input_shm_offset)) return std::nullopt;
  if(!reader.read_int32(init_cfg.cov_shm_id)) return std::nullopt;
  if(!reader.read_int32(init_cfg.cov_shm_offset)) return std::nullopt;

  uint8_t str_size;
  for (auto &sym : init_cfg.symbols) {
      if(!reader.read_uint8(str_size)) return std::nullopt;
      if (!reader.read_string(sym, str_size)) return std::nullopt;
  }

  if(reader.remaining() != 0)
    return std::nullopt;

  return init_cfg;
}


testing::status Receiver::handle_enable_mmio_tracking() 
{
  vp_manager.enable_mmio_tracking();
  log_info_message("MMIO tracking enabled");
  return testing::STATUS_OK;
}


testing::status Receiver::handle_enable_code_coverage() 
{
  vp_manager.enable_code_coverage();

  log_info_message("Code coverage enabled.");
  return testing::STATUS_OK;
}


testing::status Receiver::handle_get_return_val(uint64_t &val) 
{
  testing::status status = vp_manager.get_ret_val(val);

  log_info_message("Got return value: %d.", val);

  return status;
}


testing::status Receiver::handle_get_code_coverage_shm()
{
  if(!vp_manager.get_cov_array())
    return testing::STATUS_ERROR;

  return testing::STATUS_OK;
}


testing::status Receiver::handle_init_shm(std::vector<uint8_t>& data)
{
  uint32_t input_shm_id, input_shm_offset, cov_shm_id, cov_shm_off;
  using namespace testing::conversion;

  BufferReader reader(data);

  if(!reader.read_int32(cov_shm_id)) return testing::STATUS_ERROR;
  if(!reader.read_int32(cov_shm_off)) return testing::STATUS_ERROR;
  if(!reader.read_int32(input_shm_id)) return testing::STATUS_ERROR;
  if(!reader.read_int32(input_shm_offset)) return testing::STATUS_ERROR;

  vp_manager.init_shm(cov_shm_id, input_shm_id, input_shm_offset);

  return testing::STATUS_OK;
}


void Receiver::handle_request(testing::Request  &req, testing::Response &res) 
{
  switch (req.request_command) 
  {
    case testing::Command::ENABLE_MMIO_TRACKING: {
      if (req.data.size() != 0) { return; }

      res.response_status = handle_enable_mmio_tracking();
      res.data.clear();

      break;
    }

    case testing::Command::ENABLE_CODE_COVERAGE: {
      if (req.data.size() != 0) return;

      res.response_status = handle_enable_code_coverage();
      res.data.clear();

      break;
    }

    case testing::Command::DO_RUN_SHM: {
      if (req.data.size() != 0) return;

      res.response_status = vp_manager.run_simulation();
      res.data.clear();

      break;
    }

    case testing::Command::RUN_INIT: {

      auto config = parse_init_config(req.data);

      if(!config){
        log_error_message("Request malformed");
        testing::PipeCommHandler::respond_malformed(res);
      } else{
        res.response_status = vp_manager.run_init(*config);}

      res.data.clear();

      break;
    }

    case testing::Command::INIT_SHM: {

      res.response_status = handle_init_shm(req.data);

      res.data.clear();

      break;
    }

    case testing::Command::GET_CODE_COVERAGE_SHM: {
      if (req.data.size() != 0) {
        log_error_message("Request malformed");
        testing::PipeCommHandler::respond_malformed(res);
        return;
      }

      res.response_status = handle_get_code_coverage_shm();
      
      res.data.clear();
      break;
    }

    case testing::Command::GET_RETURN_CODE: {
      if (req.data.size() != 0) {
        log_error_message("Request malformed");
        testing::PipeCommHandler::respond_malformed(res);
        return;
      }
      uint64_t exit_code = 0;
      res.response_status = handle_get_return_val(exit_code);
      res.data.resize(sizeof(uint64_t));
      testing::conversion::int64_to_bytes(exit_code, res.data.data(), 0);
      break;
    }

    default: {
      log_error_message("Command not supported");
      break;
    }
  }
}


Receiver::~Receiver() {
  stop_receiver = true;  // Signal thread to stop

  // Wait until the thread finishes (the program would terminate immediately
  // otherwise)
  if (receiver_thread.joinable()) { receiver_thread.join(); }
}

}  // namespace avp64
