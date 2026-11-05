#ifndef CAN_INJECTOR_HPP
#define CAN_INJECTOR_HPP

#include <queue>
#include <mutex>
#include "vcml/protocols/can.h"
#include "vcml/core/component.h"

namespace fuzzing{

class CanInjector : public vcml::module, public vcml::can_host {
  private:
    std::shared_ptr<std::mutex>                  m_mtx;
    std::shared_ptr<std::queue<uint8_t>>         can_queue;

    vcml::can_frame             frame;
    vcml::sc_event              m_ev;

    void can_transmit();

  public:
    vcml::can_initiator_socket can_tx;
    vcml::can_target_socket    can_rx;  // I need it to do connect it to the canbus, but I won't use it
    bool                       is_queue_set = false;

    CanInjector(const sc_core::sc_module_name &nm);
    void set_shared_queue(std::shared_ptr<std::queue<uint8_t>> q, std::shared_ptr<std::mutex> m);
    std::function<void(std::optional<uint8_t>)> on_empty_event;
    void send_to_guest();
    void build_can_frame();

    ~CanInjector();
};

}  // namespace fuzzing

#endif
