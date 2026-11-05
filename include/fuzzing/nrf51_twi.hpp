#pragma once

#include "vcml/core/types.h"
#include "vcml/core/range.h"
#include "vcml/core/systemc.h"
#include "vcml/core/peripheral.h"
#include "vcml/core/model.h"

#include "vcml/protocols/tlm.h"
#include "vcml/protocols/gpio.h"
#include "vcml/protocols/i2c.h"

#define I2C_SLAVE_ADDR 0x10

constexpr vcml::u32 SHORT_BB_SUSPEND = 1 << 0;
constexpr vcml::u32 SHORT_BB_STOP = 1 << 1;

namespace fuzzing{

class nrf51_twi : public vcml::peripheral
{
    private:
        // hz_t m_hz;
        vcml::u8 m_tx;
        vcml::u8 m_rx;
        bool m_enable;
        vcml::u32 m_frequency;
        vcml::u32 m_slave_addr;

        void write_TASKS_STARTTX(vcml::u32 val);
        void write_TASKS_STARTRX(vcml::u32 val);
        void write_TASKS_STOP(vcml::u32 val);
        void write_TASKS_RESUME(vcml::u32 val);

        void write_FREQUENCY(vcml::u32 val);
        void write_ADDRESS(vcml::u32 val);
        void write_ENABLE(vcml::u32 val);

        void write_TXD(vcml::u32 val);
        // RX register is read only, the sw never writes to it

        // void update_irq(); not using it for now

    public:
        // Tasks
        vcml::reg<vcml::u32> TASKS_STARTRX;
        vcml::reg<vcml::u32> TASKS_STARTTX;
        vcml::reg<vcml::u32> TASKS_STOP;
        vcml::reg<vcml::u32> TASKS_SUSPEND;
        vcml::reg<vcml::u32> TASKS_RESUME;
        // Missing tasks: TASKS_SUSPEND, TASKS_RESUME
        //                0x01C          0x020

        // Events
        vcml::reg<vcml::u32> EVENTS_RXDREADY;
        vcml::reg<vcml::u32> EVENTS_TXDSENT;
        vcml::reg<vcml::u32> EVENTS_STOPPED;
        vcml::reg<vcml::u32> EVENTS_ERROR;
        vcml::reg<vcml::u32> EVENTS_BB;
        vcml::reg<vcml::u32> EVENTS_SUSPENDED;

        // Configuration
        vcml::reg<vcml::u32> PSELSCL;
        vcml::reg<vcml::u32> PSELSDA;

        vcml::reg<vcml::u32> SHORTS;
        vcml::reg<vcml::u32> INTENCLR;

        vcml::reg<vcml::u32> ERRORSRC;
        vcml::reg<vcml::u32> ENABLE;
        vcml::reg<vcml::u32> ADDRESS;
        vcml::reg<vcml::u32> FREQUENCY;
        // Missing configuration: POWER, INTENSET
        //                        0xFFC  0x304       

        // Data
        vcml::reg<vcml::u32> RXD;
        vcml::reg<vcml::u32> TXD;

        // I²C signal and IRQ
        vcml::tlm_target_socket in;
        vcml::i2c_initiator_socket i2c;
        // gpio_target_socket irq; not using it for now

        nrf51_twi(const sc_core::sc_module_name& name);
        virtual ~nrf51_twi();
        virtual void reset() override;
};

}