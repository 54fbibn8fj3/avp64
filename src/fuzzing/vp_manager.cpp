#include "fuzzing/vp_manager.hpp"
#include "fuzzing/fuzzing_logger.hpp"
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>

using namespace vcml::debugging;

namespace fuzzing {

VPManager::VPManager(const std::string &name, MMIOprobe &get_probe,
                     vcml::debugging::target &core)
    : suspender(name),
      subscriber(),
      mmio_probe(get_probe),
      target_core(core),
      is_breakpoint_hit(false),
      is_sim_suspended(false),
      current_event(std::nullopt),
      checkpoint(nullptr),
      prev_bb_loc(0),
      cov_shm(nullptr),
      ret_value(std::nullopt)
{}

void VPManager::notify_breakpoint_hit(const vcml::debugging::breakpoint &bp, const sc_core::sc_time& t) {

  suspend_simulation();

  if (bp.address() == error_symbol.addr) {
    log_info_message("Error breakpoint hit");
    ret_value = 1;
    if(checkpoint) 
      checkpoint->at_exit(ret_value.value());
    else
      handle_exit_request(ret_value.value());
  }
  else if (bp.address() == start_breakpoint.addr) {
    log_info_message("Start breakpoint hit");
    mmio_probe.set_booting_done();
    on_complete_init();
    return;
  } 
  else if (bp.address() == end_breakpoint.addr) {
    log_info_message("End breakpoint hit");
    std::pair<bool, vcml::u64> ret_val_pair = read_reg_value(ret_register);
    if (!ret_val_pair.first) {
      log_error_message("Error during return value recording!");
      return;
    }
    ret_value = ret_val_pair.second;
    log_info_message("Return value recorded: %d.", ret_value.value());
  }

  {
    std::lock_guard<std::mutex> lock(mtx);
    current_event = SimEvent::Breakpoint;
  }
  cv.notify_one();
}


void VPManager::notify_basic_block(target &tgt, mwr::u64 pc, size_t blksz,
                                   size_t offset, const sc_core::sc_time& t) {

  uint64_t curr_bb_loc = (pc >> 4) ^ (pc << 8);
  curr_bb_loc &= MAP_SIZE - 1;

  bb_array[curr_bb_loc ^ prev_bb_loc]++;
  prev_bb_loc = curr_bb_loc >> 1;
}


void VPManager::on_complete_init(){
  log_info_message("on_complete_init");

  if(checkpoint) checkpoint->unblocking_checkpoint();

  suspend_simulation();

  {
    std::lock_guard<std::mutex> lock(mtx);
    current_event = SimEvent::Checkpoint;
  }
  cv.notify_one();

  if(checkpoint) checkpoint->blocking_checkpoint();
}


testing::status VPManager::wait_for_event() {

  SimEvent ev;
  log_info_message("Waiting for an event to stop the simulation...");

  std::unique_lock<std::mutex> lock(mtx);

  bool notified = cv.wait_for(lock, std::chrono::seconds(timeout_s),
                              [this] {
                                  return current_event.has_value();
                              });

  if (!notified) {
      ev = SimEvent::Timeout;
  }

  ev = *current_event;
  current_event.reset();

  switch (ev) {
    case SimEvent::Breakpoint:
        log_info_message("Breakpoint hit");
        is_breakpoint_hit.store(false);
        return testing::STATUS_OK;

    case SimEvent::Exit:
        log_info_message("Simulation exited");
        return testing::STATUS_OK;

    case SimEvent::Timeout:
        log_error_message("Timeout");
        return testing::STATUS_ERROR;

    case SimEvent::Checkpoint:
        log_info_message("Checkpoint reached");
        return testing::STATUS_OK;

    default:
        return testing::STATUS_ERROR;
  }
  
  return testing::STATUS_OK;
}


bool VPManager::set_breakpoint(brkpt &bp) {
  log_info_message("Setting breakpoint");

  mwr::u64 addr;

  // target is a reference to each pointer in the vector
  if (const symbol *sym = target_core.symbols().find_symbol(bp.name)) {
    addr = sym->virt_addr();
  } else {
    addr = std::stoull(bp.name, nullptr, 16);
  }

  if (!target_core.insert_breakpoint(addr, this)) { return false; }
  bp.addr = addr;

  return true;
}


void VPManager::enable_mmio_tracking() {
  mmio_probe.enable_tracking();
  log_info_message("MMIO tracking enable");
}


void VPManager::enable_code_coverage() {
  target_core.trace_basic_blocks(this);
}


testing::status VPManager::get_ret_val(uint64_t &val) {
  log_info_message("Getting return value");

  if (!ret_value.has_value()) {
    log_error_message("Return code was not recorded yet!");
    return testing::STATUS_ERROR;
  }

  val = ret_value.value();

  ret_value.reset();
  return testing::STATUS_OK;
}


uint8_t *VPManager::get_cov_array() {
  log_info_message("Getting coverage array");

  return bb_array;
}



bool VPManager::attach_cov_shm(int shm_cov_id) {
    // open code coverage shm
    cov_shm = reinterpret_cast<uint8_t*>(shmat(shm_cov_id, nullptr, 0));

    if (cov_shm == reinterpret_cast<uint8_t*>(-1)) {
      log_error_message("Failed to attach cov shared memory segment");
      return false;
    }

    struct shmid_ds shm_info;
    if (shmctl(shm_cov_id, IPC_STAT, &shm_info) == -1) {
      log_error_message("Reading length of shared memory failed!");
      return false;
    }

    log_error_message("Succesfully attached to the cov shm");
    return true;
}


testing::status VPManager::write_shm_cov(int shm_cov_id){
  if(!cov_shm)
    attach_cov_shm(shm_cov_id);

  std::memcpy(cov_shm, bb_array, MAP_SIZE * sizeof(uint8_t));
  return testing::STATUS_OK;
}


void VPManager::handle_exit_request(mwr::u64 exit_code){
  log_info_message("Return value recorded: %d.", exit_code);

  ret_value = exit_code;

  {
    std::lock_guard<std::mutex> lock(mtx);
    current_event = SimEvent::Exit;
  }
  cv.notify_one();
}


void VPManager::set_checkpoint_mode(){

  switch (std::stoi(run_mode)) {
    case CRIU:{
      checkpoint = std::make_unique<CriuCheckpoint>(mmio_probe);
      break;
    }
    case FORK:{
      checkpoint = std::make_unique<ForkCheckpoint>(mmio_probe);
      break;
    }
    case HYBRID:{
      checkpoint = std::make_unique<HybridCheckpoint>(mmio_probe);
      break;
    }
    case NO_CHKPT:{
      checkpoint = nullptr;
      break;
    }
    default:{
      log_info_message("No suitable checkpoint method, running without");
      checkpoint = nullptr;
    }
  }
}


void VPManager::init_shm(uint32_t cov_id, uint32_t input_id, int offset){
  cov_shm_id = cov_id;
  mmio_probe.init_input_shm(input_id, offset);
}


testing::status VPManager::run_init(InitConfig& cfg)
{
  start_breakpoint.name = cfg.symbols[0];
  end_breakpoint.name   = cfg.symbols[1];
  ret_register          = cfg.symbols[2];
  run_mode              = cfg.symbols[3]; 
  error_symbol.name     = cfg.symbols[4];

  log_info_message("run_init");

  set_checkpoint_mode();    

  if (!start_breakpoint.is_null() && !set_breakpoint(start_breakpoint)) {
    log_error_message("Start breakpoint was not found!");
    return testing::STATUS_ERROR;
  }
  
  if (!end_breakpoint.is_null() && !set_breakpoint(end_breakpoint)) {
    log_error_message("End breakpoint was not found!");
    return testing::STATUS_ERROR;
  }

  if (!error_symbol.is_null()) { set_breakpoint(error_symbol); }

  init_shm(cfg.cov_shm_id, cfg.input_shm_id, cfg.input_shm_offset);

  mmio_probe.register_notify_booting_done([&](){
    on_complete_init();
  });

  if(!checkpoint) {
    mmio_probe.register_notify_exit_request([&](mwr::u64 exit_code){
      write_shm_cov(cov_shm_id);
      handle_exit_request(exit_code);
    });  
  } else {
    // For the checkpoint, the checkpoint class has to call it!
    checkpoint->register_exit_handler([&](mwr::u64 exit_code){
      handle_exit_request(exit_code);
    }); 
    
    checkpoint->register_fill_covshm([&](){
      write_shm_cov(cov_shm_id);
    }); 
  }

  // We will continue until the init is done!
  resume_simulation();
  return wait_for_event();
}


testing::status VPManager::run_simulation() 
{
  prev_bb_loc = 0;
  std::memset(bb_array, 0, MAP_SIZE * sizeof(uint8_t));

  resume_simulation();
  // Not super robust 
  if(checkpoint) checkpoint->notify_do_run();

  return wait_for_event();
}


void VPManager::suspend_simulation() {
  if (!is_sim_suspended) {
    log_info_message("Suspending simulation");
    is_sim_suspended = true;
    suspend();
  }
}


void VPManager::resume_simulation() {
  if (is_sim_suspended) {
    log_info_message("Continuing simulation");
    is_sim_suspended = false;
    resume();
  }
}


/* The method reads the value of a register and returns its value and
 * success/failure */
std::pair<bool, vcml::u64> VPManager::read_reg_value(std::string &reg_name) {
  log_info_message("Read_reg_value");
  vcml::u64 read_val = 0;

  const cpureg *reg = target_core.find_cpureg(reg_name);

  if (!reg) {
    log_info_message("The register with the name %s was not found!",
                     reg_name.c_str());
    return {false, -1};
  }

  if (reg->size > 8) {
    log_error_message(
        "The requested register is larger thatn 8 bytes, not supported!");
    return {false, -1};
  }

  reg->read(&read_val, reg->size);

  return {true, read_val};
}


VPManager::~VPManager(){
    // Detach the shared memory
  if (shmdt(cov_shm) == -1) {
    log_error_message("Failed to detach code coverage shared memory");
  }
}

}  // namespace avp64