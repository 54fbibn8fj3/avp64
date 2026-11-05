#include "fuzzing/can_injector.hpp"

namespace fuzzing {

void CanInjector::can_transmit() {
  while (true) {
    wait(m_ev);

    std::unique_lock<std::mutex> guard(*m_mtx);
    can_tx.send(frame);
    
  }
}


void CanInjector::set_shared_queue(std::shared_ptr<std::queue<uint8_t>> q, std::shared_ptr<std::mutex> m) {
  can_queue = q;
  m_mtx = m;
  is_queue_set = true;
}

void CanInjector::send_to_guest() {

  std::unique_lock<std::mutex> guard(*m_mtx);

  if(can_queue->empty())
      on_empty_event(std::nullopt);
  
  build_can_frame();
  vcml::on_next_update([&]() -> void { m_ev.notify(sc_core::SC_ZERO_TIME); });
}


void CanInjector::build_can_frame(){

  if(can_queue->size() < 4)
    on_empty_event(4 - can_queue->size());

  // 1) Parse 11-bit standard ID (big-endian)
  uint8_t byte0 = can_queue->front(); can_queue->pop();
  uint8_t byte1 = can_queue->front(); can_queue->pop();

  uint32_t sid = (static_cast<uint32_t>(byte0) << 8) | static_cast<uint32_t>(byte1);
  sid &= 0x7FF;  // keep 11 bits

  // 2) Flags and DLC
  uint8_t flags = can_queue->front(); can_queue->pop();
  uint8_t dlc = can_queue->front();   can_queue->pop();

  // 3) Build msgid: standard frame (no EFF), add RTR if flagged
  uint32_t msgid = sid;  // no CAN_EFF bit for standard ID
  if (flags & 0x01)      // if bit0 is RTR
      msgid |= vcml::CAN_RTR;

  frame.msgid = msgid;

  // 4) DLC + CAN FD flags
  frame.dlc = (dlc > 8) ? 8 : dlc;
  frame.flags = static_cast<uint8_t>(
      flags & (vcml::CANFD_BRS | vcml::CANFD_ESI | vcml::CANFD_FDF));

  // 5) Extract payload (assume 8 bytes always present)
  // We should add a minimum to the reg field
  for (size_t i = 0; i < frame.dlc; ++i) {
      if (can_queue->empty())
          break;
      frame.data[i] = can_queue->front();
      can_queue->pop();
  }
}

CanInjector::CanInjector(const sc_core::sc_module_name &nm)
    : module(nm),
      m_mtx(),
      can_queue(),
      frame(),
      m_ev("rxev"),
      can_tx("can_tx"),
      can_rx("can_rx"),
      is_queue_set(false) {
  SC_HAS_PROCESS(CanInjector);
  SC_THREAD(can_transmit);
}

CanInjector::~CanInjector() {
}

}  // namespace fuzzing
