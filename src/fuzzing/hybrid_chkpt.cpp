#include "fuzzing/chkpt_strategy.hpp"
#include "fuzzing/fuzzing_logger.hpp"
#include <optional>
#include <unistd.h>
#include <criu/criu.h>
#include <fcntl.h>
#include <filesystem>
#include <chrono>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>

namespace fuzzing {

HybridCheckpoint::HybridCheckpoint(MMIOprobe& mmio_probe):
probe(mmio_probe),
fork_loop_exist(false),
snapshot_exists(false),
m_socket_path("criu_service.socket"),  
m_log_lvl(LOG_LVL::LOG_DEBUG),         
m_log_file_path("criu.log"),           
m_img_dir(std::string(std::getenv("CRIU_IMG_DIR"))),              
m_img_dir_fd(-1),                      
m_initialized(false)
{
  sem_init(&sem, 0, 0);

  probe.register_notify_exit_request([&](mwr::u64 exit_code) 
  {
    at_exit(exit_code);
  }); 
}


void HybridCheckpoint::at_exit(mwr::u64 exit_code)
{
  fill_cov_shm();
  
  log_info_message("Child is exiting");
  _exit(exit_code);
}


void HybridCheckpoint::fork_chkpt() {
  log_info_message("Entering fork chkpt");

  while (true) {  

    // Do not continue until the harness says so!
    sem_wait(&sem);

    // reset shm index to read new fuzzer input from shm
    probe.shm_idx = probe.shm_offset;

    log_info_message("Fork received do_run");
    fork_loop_exist = true;

    pid_t pid = fork();

    if (pid > 0)
    {  // parent
      int status;
      uint64_t exit_code;

      log_info_message("Created child %d", pid);

      waitpid(pid, &status, 0);
      
      if (WIFEXITED(status))  // exit value from child
        exit_code = (uint64_t)WEXITSTATUS(status);
      else
        exit_code = 1; // error, child killed

      log_info_message("Transfer return code %d to harness", exit_code);
      notify_exit_request(exit_code);
    }
    else if (pid == 0){  // child

      // continue simulation
      return;
    }
  }
}


void HybridCheckpoint::register_exit_handler(std::function<void(mwr::u64)> func)
{
  notify_exit_request = std::move(func);
}


void HybridCheckpoint::register_fill_covshm(std::function<void()> func)
{
  fill_cov_shm = std::move(func);
}


void HybridCheckpoint::notify_do_run()
{
    sem_post(&sem); 
        
    return;
}


testing::status HybridCheckpoint::blocking_checkpoint(){
    
    if(!fork_loop_exist){

        if(!probe.isAttached())
            probe.attach_input_shm();

        fork_chkpt();
    }

    return testing::STATUS_OK;
}


// Why do we attach every time?
// Because the dump of criu has no knowledge of the shm
// It's not sth we can save and restore!
testing::status HybridCheckpoint::unblocking_checkpoint()
{   
  if(!snapshot_exists){
    // Detach right before CRIU, otherwise it breaks!
    if(!probe.detach_input_shm())
        return testing::STATUS_ERROR;

    take_snapshot();
    snapshot_exists = true;
  }

  return testing::STATUS_OK;
}


pid_t HybridCheckpoint::get_tracer_pid(pid_t pid) 
{
    std::stringstream proc_status_path;
    proc_status_path << "/proc/" << pid << "/status";

    std::ifstream status_fs;
    status_fs.open(proc_status_path.str(), std::ios_base::in);
    for (std::string line; std::getline(status_fs, line);) {
        const std::string search_str("TracerPid:\t");
        size_t pos = line.find(search_str);
        if (pos != std::string::npos) {
            std::string pid_str = line.substr(pos + search_str.length());
            return std::stoi(pid_str);
        }
    }
    return -1;
}


void HybridCheckpoint::save_checkpoint_pid(pid_t sim_pid) {
    std::string pid_path = std::string(m_img_dir) + "/sim_pid.txt";
    std::ofstream pid_file(pid_path);
    if (pid_file.is_open()) {
        pid_file << sim_pid;
        pid_file.close();
    } else {
        log_warn("Failed to save PID file to %s", pid_path.c_str());
    }
}


void HybridCheckpoint::take_snapshot() {
    pid_t sim_pid = getpid();

    pid_t pid = fork(); // fork to not have the criu unix socket connected

    if (pid > 0) {    // parent: wait for child to exit before continue
        int status;
        waitpid(pid, &status, 0);
    }
    else{
        if (!m_initialized) {
            snapshot_init();
        }

        pid_t tracer_pid = get_tracer_pid(sim_pid);
        VCML_ERROR_ON(tracer_pid == -1, "Failed to read tracer pid");
        VCML_ERROR_ON(tracer_pid != 0, "traced by %d", tracer_pid);

#ifdef HAVE_LIBCRIU
        criu_set_pid(sim_pid);
        save_checkpoint_pid(sim_pid);

        /*
        * The simulation shares common resources with the shell (e.g., session,
        * terminal). `--shell-job` needs to be enabled, because only a part of the
        * session is dumped (e.g., slave end of a tty pair)
        */
        criu_set_shell_job(true);

        /*
        * leave simulation running after dump because of pipes
        */
        criu_set_leave_running(true);

        /*
        * Checkpoint established TCP connections
        */
        criu_set_tcp_established(true);

        if(is_error(criu_dump()))
        {
            close(m_img_dir_fd);
            std::filesystem::remove_all(m_img_dir);

            VCML_ERROR_ON(true, "Failed to create checkpoint");
        }
        
#else
    log_error("build without CRIU - checkpointing is not supported");
#endif
        exit(0); // exit forked child process
    }

}


void HybridCheckpoint::snapshot_init() {
    if (m_initialized) {
        return;
    }

#ifdef HAVE_LIBCRIU
    log_info("Initizalizing chkpt");
    VCML_ERROR_ON(criu_init_opts() != 0, "failed to initialize criu");

    VCML_ERROR_ON(!std::filesystem::is_socket(m_socket_path),
                "The criu socket `%s` does not exist",
                m_socket_path.c_str());
    criu_set_service_address(m_socket_path.c_str());

    if(m_img_dir.empty()){
        log_warn("criu image dir is not a valid name, using the default folder name `checkpoints`");
        m_img_dir = "checkpoints";
    }

    if (!std::filesystem::is_directory(m_img_dir)) {
        log_warn("criu image dir `%s` does not exist - creating dir...",
                m_img_dir.c_str());
        std::filesystem::create_directories(m_img_dir);
    }

    VCML_ERROR_ON(!std::filesystem::is_directory(m_img_dir),
                "criu image dir `%s` does not exist", m_img_dir.c_str());
    m_img_dir_fd = open(m_img_dir.c_str(), O_DIRECTORY);
    VCML_ERROR_ON(m_img_dir_fd < 0, "failed to open criu image dir `%s`",
                m_img_dir.c_str());
    criu_set_images_dir_fd(m_img_dir_fd);

    criu_set_log_file(m_log_file_path.c_str());
    criu_set_log_level(m_log_lvl);

    m_initialized = true;
#else
    log_error("build without CRIU - checkpointing is not supported");
#endif
}


bool HybridCheckpoint::is_error(const int retval) const {
    switch (retval) {
    case -EBADE:
        log_error("RPC has returned fail");
        return true;
    case -ECONNREFUSED:
        log_error("Unable to connect to CRIU");
        return true;
    case -ECOMM:
        log_error("Unable to send/recv msg to/from CRIU");
        return true;
    case -EINVAL:
        log_error(
            "CRIU doesn't support this type of request. You should probably "
            "update CRIU.");
        return true;
    case -EBADMSG:
        log_error(
            "Unexpected response from CRIU. You should probably update CRIU.");
        return true;
    default:
        if (retval < 0) {
            log_error("Unknown CRIU error");
            return true;
        }
        return false;
    }
}


HybridCheckpoint::~HybridCheckpoint() {
  sem_destroy(&sem);
}


}