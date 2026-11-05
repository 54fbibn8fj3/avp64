#ifndef MMIO_PROBE_HPP
#define MMIO_PROBE_HPP

#include <cstdint>
#include <functional>
#include <optional>
#include <utility>
#include <mutex>
#include "vcml/core/component.h"
#include "mmio_register_file.hpp"
#include "fuzzing/uart_injector.hpp"
#include "fuzzing/can_injector.hpp"
#include "fuzzing/i2c_injector.hpp"
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>


namespace fuzzing {

class MMIOprobe : public vcml::component {

 public:
  vcml::tlm_target_socket    probe_in;
  vcml::tlm_initiator_socket probe_out;

  UartInjector &uart_inj;
  UartInjector &uart1_inj;
  I2CInjector &i2c_inj;
  CanInjector  &can_inj;

  std::shared_ptr<std::mutex> mtx;
  unsigned char* shm_ptr;
  int shm_key;
  int shm_offset;
  int shm_idx = 0;

  explicit MMIOprobe(const vcml::sc_module_name &nm, UartInjector &uart_inj, UartInjector &uart1_inj, I2CInjector& i2c_inj, CanInjector&  can_inj);

  void reset() override;

  void enable_tracking();
  void disable_tracking();

  void init_input_shm(int id, int offset);
  bool attach_input_shm();
  bool detach_input_shm();
  bool isAttached();

  void set_booting_done();

  std::optional<mwr::u64> get_exit_requested() const;
  void register_notify_exit_request(std::function<void(mwr::u64)> func);
  void register_notify_booting_done(std::function<void()> func);
  void register_notify_reset_coverage(std::function<void()> func);

 protected:
  void before_end_of_elaboration() override;

 private:

  MMIO_register_file reg_file;
  std::vector<MMIO_register*> pending_injections; // PS c++ containers cannot store references, so use * not &
  bool is_booting_done;
  bool should_forward;

  void fill_read_queue(std::shared_ptr<std::queue<uint8_t>>& data_queue, std::optional<uint8_t> len);

  bool is_tracking_enabled = false;
  bool is_periph_enabled = false;

  std::optional<mwr::u64> exit_requested = std::nullopt;

  // This method injects data into the peripheral
  void forward_to_peripheral(std::string& periph, std::shared_ptr<std::queue<uint8_t>>& data_queue);

  // Per-peripheral flags
  std::unordered_map<std::string, bool>                       interrupt_enabled;
  std::unordered_map<std::string, sc_core::sc_process_handle> interrupt_handles;

  void start_interrupt_loop(MMIO_register &reg, sc_core::sc_time period);

  bool get_direct_mem_ptr(vcml::tlm_target_socket   &origin,
                          vcml::tlm_generic_payload &tx,
                          vcml::tlm_dmi             &dmi) override;

  void b_transport(vcml::tlm_target_socket   &origin,
                   vcml::tlm_generic_payload &tx, vcml::sc_time &dt) override;

  unsigned int transport_dbg(vcml::tlm_target_socket   &origin,
                             vcml::tlm_generic_payload &tx) override;

  std::function<void(mwr::u64)> notify_exit_request;
  std::function<void()> notify_booting_done;
  std::function<void()> reset_coverage;

  void on_reg_write(MMIO_register& reg, vcml::tlm_generic_payload& tx);

  /* helper functions */
  static inline void validate_transaction(vcml::tlm_generic_payload &tx);
  bool handle_interrupt_trigger(MMIO_register             *reg,
                                vcml::tlm_generic_payload &tx);

  void handle_exit_request(vcml::tlm_generic_payload &tx);
};
}  // namespace fuzzing

#endif  // !PROBE_HPP
