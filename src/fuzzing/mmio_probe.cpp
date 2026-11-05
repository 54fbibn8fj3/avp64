#include "fuzzing/mmio_probe.hpp"
#include <tlm_core/tlm_2/tlm_generic_payload/tlm_gp.h>
#include <cstring>
#include <utility>
#include "fuzzing/fuzzing_logger.hpp"
#include "vcml/core/systemc.h"
#include <unistd.h>

namespace fuzzing {

MMIOprobe::MMIOprobe(const vcml::sc_module_name &nm, UartInjector &uart_inj, UartInjector &uart1_inj, I2CInjector& i2c_inj, CanInjector&  can_inj)
    : vcml::component(nm), 
      probe_in("probe_in"), 
      probe_out("probe_out"),
      uart_inj(uart_inj),
      uart1_inj(uart1_inj),
      i2c_inj(i2c_inj),
      can_inj(can_inj),
      mtx(std::make_shared<std::mutex>()),
      should_forward(true) 
{}

void MMIOprobe::reset() {
  component::reset();
}


void MMIOprobe::init_input_shm(int id, int offset){
  log_info_message("set_input_shm");

  shm_key = id;
  shm_offset = offset;
  shm_idx = offset;

  attach_input_shm();
}


bool MMIOprobe::isAttached()
{
    return shm_ptr != nullptr;
}


bool MMIOprobe::attach_input_shm()
{
  log_info_message("Attaching to input shm");
  void* addr = shmat(shm_key, nullptr, SHM_RDONLY);

  if (addr == (void*)-1) {
    log_error_message("Failed to attach shared memory segment");
    return false;
  }

  shm_ptr = static_cast<uint8_t*>(addr);

  struct shmid_ds shm_info;
  if (shmctl(shm_key, IPC_STAT, &shm_info) == -1) {
    log_error_message("Reading length of shared memory failed!");
    return false;
  }
  
  return true;
}

bool MMIOprobe::detach_input_shm()
{
  log_info_message("Detaching from input shm");

  // Detach from shm
  if (shmdt(shm_ptr) == -1){
    log_error_message("Failed to detach input shared memory");
    return false;
  }

  // Invalidate the pointer
  shm_ptr = nullptr;
  // Reset the index
  shm_idx = shm_offset;
  return true;
}

void MMIOprobe::enable_tracking() {
  is_tracking_enabled = true;
}

void MMIOprobe::disable_tracking() {
  is_tracking_enabled = false;
}


void MMIOprobe::set_booting_done(){
  if(is_tracking_enabled)
    is_booting_done = true;
}


// We read from the shm, the first element we read is the number of bytes to consume
void MMIOprobe::fill_read_queue(std::shared_ptr<std::queue<uint8_t>>& data_queue, std::optional<uint8_t> len) 
{
  //log_info_message("fill_read_queue");

  const uint8_t max_chunck_data = 10;

  if (!shm_ptr){ //Check before accessing that it was assigned
    if(!attach_input_shm()) return;
  }
  
  if(!len.has_value()){
    uint8_t fuzz_len = (shm_ptr[shm_idx] < max_chunck_data) ? shm_ptr[shm_idx] : max_chunck_data;
    // Check that it's not 0
    fuzz_len = (fuzz_len==0)? 1 : fuzz_len;
    len.emplace(fuzz_len);
  }

  log_info("MMIO_PROBE: filling queue with 0x%x", len.value());

  for(int i=0; i < len.value(); ++i)
    data_queue->push(shm_ptr[shm_idx + i]);

  shm_idx += len.value();
}


void MMIOprobe::before_end_of_elaboration() {
  component::before_end_of_elaboration();
  if (!clk.is_bound()) { clk.stub(100 * mwr::MHz); }

  if (!rst.is_bound()) {
    rst.stub();
    reset();
  }
}


bool MMIOprobe::get_direct_mem_ptr(vcml::tlm_target_socket & /*origin*/,
                                   vcml::tlm_generic_payload &tx,
                                   vcml::tlm_dmi             &dmi) {
  bool use_dmi = probe_out->get_direct_mem_ptr(tx, dmi);

  if (!use_dmi) { return false; }

  uint64_t s = dmi.get_start_address();
  uint64_t e = dmi.get_end_address();

  dmi.set_start_address(s);
  dmi.set_end_address(e);

  return true;
}


// Also for every memory access there's a check? it looks inefficient
void MMIOprobe::b_transport(vcml::tlm_target_socket & /*origin*/,
                            vcml::tlm_generic_payload &tx, vcml::sc_time &dt) {
  
  validate_transaction(tx);

  // Just forward tx is tracking is not enabled
  if (!is_tracking_enabled){
    probe_out.b_transport(tx, dt);
    return;
  } 

  tlm::tlm_command tx_cmd = tx.get_command();
  uint64_t tx_addr = tx.get_address();

  MMIO_register* reg = reg_file.find(tx_addr);
  if(reg && tx_cmd == tlm::TLM_WRITE_COMMAND)
    on_reg_write(*reg, tx);


  for (auto reg_it = pending_injections.begin(); reg_it != pending_injections.end(); ){
    if (is_booting_done && handle_interrupt_trigger(*reg_it, tx)) 
      reg_it = pending_injections.erase(reg_it); // Erasing from a vector invalidates the iterator,
     else                                        // Now the returned iterator points to the element that followed the erased one
      ++reg_it;
  }
  
  if(should_forward)
    probe_out.b_transport(tx, dt);
  else 
    tx.set_response_status(vcml::TLM_OK_RESPONSE);
}


/* This method calls functions depending on the action specified in the json file */
void MMIOprobe::on_reg_write(MMIO_register& reg, vcml::tlm_generic_payload& tx){

  // I can also see this being a list
  auto action = reg.on_write;

  if(!action.has_value())
    return;

  switch(action.value())
  {
    case MMIO_action::NotifySimEnd:
      log_info_message("Simdev exit code requested, stopping simulation and notifying waiting thread");
      handle_exit_request(tx);
      break;

    case MMIO_action::NotifyInitEnd:
      notify_booting_done();
      is_booting_done = true;
      break;

    case MMIO_action::ApplyMask:{
      uint8_t* data_ptr = tx.get_data_ptr();
      uint8_t data_len = tx.get_data_length();

      reg.apply_mask(data_ptr, data_len);
    } break;
    
    case MMIO_action::StartInjection:
      if(!reg.is_ready_to_receive()){
        log_info_message("Peripheral ready to receive");
        reg.set_ready_to_receive();
        pending_injections.push_back(&reg);
      } 
      break;

    case MMIO_action::None:
      log_info_message("Nothing to do for register %s", reg.name.c_str());
      break;

    default:
      log_error_message("Register has an unknown action");
      break;
  }

}


/* This function start the injection loop */
bool MMIOprobe::handle_interrupt_trigger(MMIO_register *reg, vcml::tlm_generic_payload &tx) 
{
  log_info_message("handle_interrupt_trigger");

  if(reg->start_injection()){
    start_interrupt_loop(*reg, sc_core::sc_time(reg->interval_ms.value(), sc_core::SC_MS));
    reg->set_has_handler();
    return true; // no longer pending
  }
  return false; // still pending
}


unsigned int MMIOprobe::transport_dbg(vcml::tlm_target_socket & /*origin*/,
                                      vcml::tlm_generic_payload &tx) {
  return probe_out->transport_dbg(tx);
}

inline void MMIOprobe::validate_transaction(vcml::tlm_generic_payload &tx) {
  VCML_ERROR_ON(tx.get_data_ptr() == nullptr,
                "Transaction data pointer cannot be null");
  VCML_ERROR_ON(tx.get_data_length() == 0,
                "Transaction data length cannot be zero");
  VCML_ERROR_ON(tx.get_response_status() != vcml::TLM_INCOMPLETE_RESPONSE,
                "Invalid in-bound transaction response status");
}


/* This function starts a process that periodically injects data */
void MMIOprobe::start_interrupt_loop(MMIO_register& reg, sc_core::sc_time period)
{
  log_info_message("start_interrupt_loop");

  std::string& periph = reg.peripheral;
  auto queue_ptr = reg.data_queue;  // copy of shared_ptr 

  // If we already have a process that injects data return (avoid re-spawning)
  if(interrupt_handles[periph].valid())
    return;

  log_info_message("New injecting handle registered");
  // The lambda may run after the start_interrupt_loop() has returned, we pass interrupt_handles
  // by reference to avoid stale copies, and periph & queue_ptr by value (due to possible rehashing
  // we cannot have a reference of a map in the lambda or we get a dangling reference)
  // PS "this" is needed to access member functions and variables
  //     without mutable the by-value copies would be const and not modifiable
  auto handle = sc_core::sc_spawn( [this, queue_ptr, periph, period]() mutable { 
      log_info_message("thread started");

      while(true)
      {                   
        wait(period);
        log_info_message("Data injected with interrupt");
        forward_to_peripheral(periph, queue_ptr);
      }
  });

  interrupt_handles[periph] = handle;
}


/* This method creates a new payload and sends the fuzzing data to the bus/peripheral */
void MMIOprobe::forward_to_peripheral(std::string& periph,
                                      std::shared_ptr<std::queue<uint8_t>>& data_queue) 
{
  log_info_message("forward_to_peripheral");

  if(periph == "UART"){
    if (!uart_inj.is_queue_set){
      uart_inj.on_empty_event = [this, data_queue](std::optional<uint8_t> len) mutable {this->fill_read_queue(data_queue, len);};
      uart_inj.set_shared_queue(data_queue, mtx);
    }
    uart_inj.send_to_guest(); 
  } else if (periph == "UART1"){
    if (!uart1_inj.is_queue_set){
      uart1_inj.on_empty_event = [this, data_queue](std::optional<uint8_t> len) mutable {this->fill_read_queue(data_queue, len);};
      uart1_inj.set_shared_queue(data_queue, mtx);
    }
    uart1_inj.send_to_guest(); 
  } else if (periph == "I2C"){
    if (!i2c_inj.is_queue_set){
      i2c_inj.on_empty_event = [this, data_queue](std::optional<uint8_t> len) mutable {this->fill_read_queue(data_queue, len);};
      i2c_inj.set_shared_queue(data_queue, mtx);
    }
  }else if (periph == "CAN"){
    if (!can_inj.is_queue_set){
      can_inj.on_empty_event = [this, data_queue](std::optional<uint8_t> len) mutable {this->fill_read_queue(data_queue, len);};
      can_inj.set_shared_queue(data_queue, mtx);
    }
    can_inj.send_to_guest();
  }
  else
    VCML_ERROR("Unknown injection address");  
}


// Call lambda function in VPManager::run_init, if notify_checkpoint() is called 
// notify_checkpoint() ^= vp_manager->fork_chkpt()
void MMIOprobe::register_notify_booting_done(std::function<void()> func) {
    notify_booting_done = std::move(func);
}


// This is done exclusively to help the fuzzer analize better the coverage that it receives
// It has no logical or functional purpose. The fuzzer should not give too much importance to
// code that it executes before we inject data. It can look like we're starting to get coverage
// right after the booting sequence is done, but apparently even 100 edges out of 2k can have a negative impact
void MMIOprobe::register_notify_reset_coverage(std::function<void()> func) {
    reset_coverage = std::move(func);
}


// return recorded value
// used to continue waiting thread in VPManager::continue_simulation() in case of a exit request through simdev
std::optional<mwr::u64> MMIOprobe::get_exit_requested() const {
  return exit_requested;
}


// Call lambda function in VPManager::run_init(), if notify_exit_request(value) is called 
// notify_exit_request(value) ^= {vp_manager->ret_value = value; vp_manager->cv.notify_one();}
void MMIOprobe::register_notify_exit_request(std::function<void(mwr::u64)> func) 
{
  notify_exit_request = std::move(func);
}


void MMIOprobe::handle_exit_request(vcml::tlm_generic_payload &tx) {
  mwr::u64       exit_code = 0;
  unsigned char *data_ptr = tx.get_data_ptr();
  unsigned int   data_length = std::min((long unsigned int)tx.get_data_length(), sizeof(exit_code));

  std::memcpy(&exit_code, data_ptr, data_length); // This copies the recorded exit code to exit_code

  exit_requested = exit_code; // sets get_exit_requested().has_value() == true for waiting thread in VPManager::continue_simulation(). Also saves the return value inside is_simdev_access 
  notify_exit_request(exit_code); // Callback to lambda function in VPManager::run_simulation(...), where cv is notified and ret_value set
  should_forward = false;
}

}  // namespace fuzzing