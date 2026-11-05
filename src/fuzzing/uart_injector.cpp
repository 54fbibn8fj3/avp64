#include "fuzzing/uart_injector.hpp"
#include "fuzzing/fuzzing_logger.hpp"
#include <optional>

namespace fuzzing {

void UartInjector::uart_transmit() {
  while (true) {
    wait(sc_ev);

    std::unique_lock<std::mutex> guard(*m_mtx);
    log_info("UART INJECTOR: data sent: 0x%08x", uart_data);
    uart_tx.send(uart_data);
  }
}

void UartInjector::send_to_guest() {
  std::unique_lock<std::mutex> guard(*m_mtx);

  std::optional<uint8_t> len;
  len.emplace(1);

  if(uart_queue->empty())
      on_empty_event(len);

  uart_data = uart_queue->front();
  uart_queue->pop();
  vcml::on_next_update([&]() -> void { sc_ev.notify(sc_core::SC_ZERO_TIME); });
}


void UartInjector::set_shared_queue(std::shared_ptr<std::queue<uint8_t>> q, std::shared_ptr<std::mutex> m) {
  uart_queue = q;
  m_mtx = m;
  is_queue_set = true;
}


UartInjector::UartInjector(const sc_core::sc_module_name &nm)
    : module(nm),
      m_mtx(),
      sc_ev("rxev"),
      uart_tx("uart_tx"){
  SC_HAS_PROCESS(UartInjector);
  SC_THREAD(uart_transmit);
}

UartInjector::~UartInjector() {
}

}  // namespace fuzzing
