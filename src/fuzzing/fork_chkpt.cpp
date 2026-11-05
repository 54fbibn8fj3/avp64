#include "fuzzing/chkpt_strategy.hpp"
#include "fuzzing/fuzzing_logger.hpp"
#include <sys/wait.h>
#include <unistd.h>

namespace fuzzing {

ForkCheckpoint::ForkCheckpoint(MMIOprobe& mmio_probe):
probe(mmio_probe),
fork_loop_exist(false)
{
  sem_init(&sem, 0, 0);

  probe.register_notify_exit_request([&](mwr::u64 exit_code) 
  {
    at_exit(exit_code);
  }); 
}


void ForkCheckpoint::fork_chkpt() {
  log_info_message("Entering fork chkpt");

  while (true) {  

    // Do not continue until the harness says so!
    sem_wait(&sem);
    // std::unique_lock<std::mutex> lock(mtx);
    // cv.wait(lock);

    // reset shm index to read new fuzzer input from shm
    // probe.shm_idx = probe.shm_offset;

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


void ForkCheckpoint::register_exit_handler(std::function<void(mwr::u64)> func)
{
  notify_exit_request = std::move(func);
}

void ForkCheckpoint::register_fill_covshm(std::function<void()> func)
{
  fill_cov_shm = std::move(func);
}


// This child process cannot wake up the continue thread in vp_manager
// there's no such thread in this process! The fork does not preserve it
void ForkCheckpoint::at_exit(mwr::u64 exit_code)
{
  fill_cov_shm();
  // exit simulation
 _exit(exit_code);
}


void ForkCheckpoint::notify_do_run(){
  // std::unique_lock<std::mutex> lock(mtx);
  // cv.notify_one();
  sem_post(&sem);
}


testing::status ForkCheckpoint::unblocking_checkpoint(){
  return testing::STATUS_OK;
}

// Why is trigger_checkpoint() and not notify_do_run() that creates the fork loop?
// Because notify_do_run() is called in the receiver thread and we never exit this loop
// So by letting notify_do_run() create the loop we would indeed block the command receive
testing::status ForkCheckpoint::blocking_checkpoint(){

  if(!fork_loop_exist)
    fork_chkpt();
  
  return testing::STATUS_OK;
}


ForkCheckpoint::~ForkCheckpoint() {
  sem_destroy(&sem);
}


} //fuzzing
