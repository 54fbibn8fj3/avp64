#include "fuzzing/nrf51_twi.hpp"

namespace fuzzing {

nrf51_twi::nrf51_twi(const sc_core::sc_module_name& name):
    vcml::peripheral(name),
    m_tx(0xff),
    m_rx(0xff),
    m_enable(false),
    m_frequency(0x0),
    m_slave_addr(I2C_SLAVE_ADDR),
    TASKS_STARTRX("TASKS_STARTRX", 0x000),
    TASKS_STARTTX("TASKS_STARTTX", 0x008),
    TASKS_STOP("TASKS_STOP", 0x014),
    TASKS_SUSPEND("TASKS_SUSPEND", 0x01C),
    TASKS_RESUME("TASKS_RESUME", 0x020),
    EVENTS_RXDREADY("EVENTS_RXDREADY", 0x108),
    EVENTS_TXDSENT("EVENTS_TXDSENT",   0x11C),
    EVENTS_STOPPED("EVENTS_STOPPED",   0x104),
    EVENTS_ERROR("EVENTS_ERROR",   0x124),
    EVENTS_BB("EVENTS_BB",   0x138),
    EVENTS_SUSPENDED("EVENTS_SUSPENDED",   0x148),
    PSELSCL("PSELSCL", 0x508),
    PSELSDA("PSELSDA", 0x50C),
    SHORTS("SHORTS", 0x200),
    INTENCLR("INTENCLR", 0x308),
    ERRORSRC("ERRORSRC", 0x4C4),
    ENABLE("ENABLE", 0x500),
    ADDRESS("ADDRESS", 0x588),
    FREQUENCY("FREQUENCY", 0x524),
    RXD("RXD", 0x518),
    TXD("TXD", 0x51C),
    in("in"),
    i2c("i2c")
    {
        // Write callbacks
        TASKS_STARTTX.on_write(&nrf51_twi::write_TASKS_STARTTX); 
        TASKS_STARTRX.on_write(&nrf51_twi::write_TASKS_STARTRX);
        TASKS_RESUME.on_write(&nrf51_twi::write_TASKS_RESUME);
        TASKS_STOP.on_write(&nrf51_twi::write_TASKS_STOP);

        // TASKS_SUSPEND & TASKS_RESUME are useless as EVENTS_SUSPENDED is useless
        TASKS_SUSPEND.on_write([&](vcml::u32 val) {
            EVENTS_SUSPENDED = val;
        });

        // For EVENTS_xxx registers, only writing 0 has effects
        // Hardware sets them to 1 when the event occurs.
        EVENTS_RXDREADY.on_write([&](vcml::u32 val) {
            if(val == 0)
                EVENTS_RXDREADY = val;
        });

        EVENTS_TXDSENT.on_write([&](vcml::u32 val) {
            if(val == 0)
                EVENTS_TXDSENT = val;
        });

        EVENTS_STOPPED.on_write([&](vcml::u32 val) {
            if(val == 0)
                EVENTS_STOPPED = val;
        });

        EVENTS_ERROR.on_write([&](vcml::u32 val) {
            if(val == 0)
                EVENTS_ERROR = val;
        });


        EVENTS_BB.on_write([&](vcml::u32 val) {
            if(val == 0)
                EVENTS_BB = val;
        });


        EVENTS_SUSPENDED.on_write([&](vcml::u32 val) {
            if(val == 0)
                EVENTS_SUSPENDED = val;
        });


        PSELSCL.on_write([&](vcml::u32 val) {
            PSELSCL = val;
        });


        PSELSDA.on_write([&](vcml::u32 val) {
            PSELSDA = val;
        });

        SHORTS.allow_read_write();
        SHORTS.on_write([&](vcml::u32 val){
            SHORTS = val;
        });
        SHORTS.on_read([&]() -> vcml::u32 { return SHORTS; }); 

        INTENCLR.on_write([&](vcml::u32 val){
            INTENCLR = val;
        });

        ERRORSRC.allow_read_write();
        ERRORSRC.on_write([&](vcml::u32 val){
            ERRORSRC = val;
        });
        ERRORSRC.on_read([&]() -> vcml::u32 { return ERRORSRC; }); 

        FREQUENCY.allow_read_write();
        FREQUENCY.on_write(&nrf51_twi::write_FREQUENCY);
        FREQUENCY.on_read([&]() -> vcml::u32 { return m_frequency; }); 

        ENABLE.allow_read_write();
        ENABLE.on_write(&nrf51_twi::write_ENABLE);
        ENABLE.on_read([&]() -> vcml::u32 { return ENABLE; }); 

        ADDRESS.allow_read_write();
        ADDRESS.on_write(&nrf51_twi::write_ADDRESS);
        ADDRESS.on_read([&]() -> vcml::u32 { return static_cast<vcml::u32>(m_slave_addr); }); 

        // TXD is write-only
        TXD.on_write(&nrf51_twi::write_TXD);
        // RXD is read-only
        RXD.allow_read_only();
        RXD.on_read([&]() -> vcml::u8 { return m_rx; });
    }


void nrf51_twi::write_TASKS_STARTTX(vcml::u32 val) {
    if (!m_enable) {
        log_debug("TWI not enabled, ignoring task");
        return;
    }

    if ((ENABLE & 0x5) != 0x5) // Must be enabled in master mode
        return;

    // The full address byte is: [address (7 bits) << 1] | [R/W bit]
    vcml::u8 addr = m_slave_addr << 1; // LSB = 0 for write
    vcml::i2c_response ack = i2c.start(addr);
    if (vcml::success(ack)) {
        EVENTS_TXDSENT = 1;
    }
    else {
        EVENTS_ERROR = 1;
        ERRORSRC |= 1 << 1; // ANACK, because the slave didnt acknoledge the addr
    }
    // update_irq();
}


void nrf51_twi::write_TASKS_STARTRX(vcml::u32 val) {
    if (!m_enable || (ENABLE & 0x5) != 0x5) {
        log_debug("TWI not enabled, ignoring task");
        return;
    }


    // The full address byte is: [address (7 bits) << 1] | [R/W bit]
    vcml::u8 addr = (m_slave_addr << 1) | 0x1; // LSB = 1 for read
    vcml::i2c_response ack = i2c.start(addr);

    // After the address is ACKed, the first byte can be read immediately
    if (vcml::success(ack)) 
    {
        i2c.transport(m_rx);
        RXD = m_rx;

        // BB is raised after each transmitted or received data byte
        EVENTS_RXDREADY = 1; 
        EVENTS_BB = 1;

        // Trigger any SHORTS tied to BB
        if (SHORTS & SHORT_BB_SUSPEND) EVENTS_SUSPENDED = 1;   // BB->SUSPEND
    }
    else {
        EVENTS_ERROR = 1;
        ERRORSRC |= 1 << 1; // ANACK
    }
    //update_irq();
}

void nrf51_twi::write_TASKS_RESUME(vcml::u32 val) {
    if (!m_enable) return;
    i2c.transport(m_rx);
    RXD = m_rx;

    EVENTS_RXDREADY = 1;
    EVENTS_BB = 1;
    if (SHORTS & SHORT_BB_STOP) {
        write_TASKS_STOP(1);
    }
}
void nrf51_twi::write_TASKS_STOP(vcml::u32 val) {
    i2c.stop();
    EVENTS_STOPPED = 1;
    //update_irq();
}

// Do we care about delays?
void nrf51_twi::write_FREQUENCY(vcml::u32 val) {
    m_frequency = val;
}


void nrf51_twi::write_ENABLE(vcml::u32 value) {
    if (value == 0x5) {
        m_enable = true;
        log_debug("TWI enabled");
    } else if (value == 0) {
        m_enable = false;
        log_debug("TWI disabled");
    } else {
        log_warn("Invalid value written to ENABLE: 0x%08x", value);
    }

    ENABLE = value;
}


void nrf51_twi::write_ADDRESS(vcml::u32 val) {
    if (val > 0x7F) {
        log_warn("invalid TWI address: 0x%02x", val);
        return;
    }

    // The I2C address is 7 bits
    m_slave_addr = static_cast<vcml::u8>(val & 0x7F);
    ADDRESS = val;
    log_debug("set TWI slave address to 0x%02x", m_slave_addr);
}


void nrf51_twi::write_TXD(vcml::u32 val) {
    m_tx = val & 0xFF;
    vcml::i2c_response ack = i2c.transport(m_tx);

    if (vcml::success(ack)) 
    {
        EVENTS_BB = 1;
        EVENTS_TXDSENT = 1;

        if (SHORTS & (1 << 0)) // BB->SUSPEND
            EVENTS_SUSPENDED = 1; // This does nothing, it is there only for compliance reason
        if (SHORTS & (1 << 1)) // BB->STOP
            write_TASKS_STOP(1);
    } else 
    {
        EVENTS_ERROR = 1;
        ERRORSRC |= 1 << 2; // bit 2 = DNACK
    }
    //update_irq();
}


nrf51_twi::~nrf51_twi() = default;


void nrf51_twi::reset() {
    m_frequency = 0;
    m_slave_addr = 0;
    m_enable = false;
    m_tx = 0xff;
    m_rx = 0xff;
    vcml::peripheral::reset();
}

// Do I need VCML_EXPORT_MODEL?

}