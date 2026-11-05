#ifndef I2C_INJECTOR_HPP
#define I2C_INJECTOR_HPP

#include <queue>
#include <mutex>
#include "vcml/core/types.h"
#include "vcml/core/systemc.h"
#include "vcml/protocols/i2c.h"
#include "vcml/core/component.h"

#define I2C_SLAVE_ADDR 0x10

namespace fuzzing {

class I2CInjector : public vcml::module, public vcml::i2c_host {
 private:
  std::shared_ptr<std::mutex>          m_mtx;
  std::shared_ptr<std::queue<uint8_t>> i2c_queue;

 public:
  bool is_queue_set;
  std::function<void(std::optional<uint8_t>)> on_empty_event;

  vcml::i2c_target_socket                      i2c;  
  vcml::property<vcml::u8>                     i2c_addr;

  I2CInjector(const sc_core::sc_module_name &nm);

  void set_shared_queue(std::shared_ptr<std::queue<uint8_t>> q, std::shared_ptr<std::mutex> m);

  vcml::i2c_response i2c_start(const vcml::i2c_target_socket& socket, vcml::tlm_command command) override;
  vcml::i2c_response i2c_stop(const vcml::i2c_target_socket& socket) override;
  vcml::i2c_response i2c_read(const vcml::i2c_target_socket& socket, vcml::u8& data) override;
  vcml::i2c_response i2c_write(const vcml::i2c_target_socket& socket, vcml::u8 data) override;

  ~I2CInjector();
};

}  // namespace fuzzing

#endif
