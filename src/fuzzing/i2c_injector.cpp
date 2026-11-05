#include "fuzzing/i2c_injector.hpp"
#include "fuzzing/fuzzing_logger.hpp"

namespace fuzzing {

/* How do we deal with the address?: We manipulate it when ADDRESS is accessed */
/* Is i2c_queue valid once fuzz_queue is not valid anymore? */
/* When do we erase the data of both? */

vcml::i2c_response I2CInjector::i2c_start(const vcml::i2c_target_socket& socket,
                             vcml::tlm_command command) {
    return vcml::I2C_ACK;
}


vcml::i2c_response I2CInjector::i2c_stop(const vcml::i2c_target_socket& socket) {
    return vcml::I2C_ACK;
}


vcml::i2c_response I2CInjector::i2c_read(const vcml::i2c_target_socket& socket, vcml::u8& data) {
    std::unique_lock<std::mutex> guard(*m_mtx);

    if(i2c_queue->empty())
      on_empty_event(std::nullopt);

    data = i2c_queue->front();
    log_info("I2C INJECTOR: data sent: 0x%08x", data);
    i2c_queue->pop();

    return vcml::I2C_ACK;
}


vcml::i2c_response I2CInjector::i2c_write(const vcml::i2c_target_socket& socket, vcml::u8 data) {
    return vcml::I2C_ACK;
}


void I2CInjector::set_shared_queue(std::shared_ptr<std::queue<uint8_t>> q, std::shared_ptr<std::mutex> m) {
  i2c_queue = q;
  m_mtx = m;
  is_queue_set = true;
}


I2CInjector::I2CInjector(const sc_core::sc_module_name &nm)
    : module(nm),
      i2c_host(),
      m_mtx(),
      i2c_queue(),
      is_queue_set(false),
      i2c("i2c"),
      i2c_addr("i2c_addr", I2C_SLAVE_ADDR) {
        i2c.set_address(i2c_addr);
}


I2CInjector::~I2CInjector() {
}

}  // namespace fuzzing
