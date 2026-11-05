#ifndef UART_INJECTOR_HPP
#define UART_INJECTOR_HPP

#include "vcml/core/component.h"
#include "vcml/protocols/serial.h"

namespace fuzzing{

class UartInjector : public vcml::module, public vcml::serial_host{
    private:
        std::shared_ptr<std::mutex>                  m_mtx;
        std::shared_ptr<std::queue<uint8_t>>         uart_queue;
        vcml::sc_event                               sc_ev;
        uint8_t                                      uart_data;

        void uart_transmit();

    public:
        vcml::serial_initiator_socket                uart_tx;
        bool                                         is_queue_set;
        
        UartInjector(const sc_core::sc_module_name &nm);

        std::function<void(std::optional<uint8_t>)> on_empty_event;
        void send_to_guest();
        void set_shared_queue(std::shared_ptr<std::queue<uint8_t>> q, std::shared_ptr<std::mutex> m);

        ~UartInjector();
};

} //namespace fuzzing

#endif