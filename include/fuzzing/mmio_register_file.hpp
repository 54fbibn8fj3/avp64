#ifndef REG_FILE_HPP
#define REG_FILE_HPP

#include <optional>
#include <cstdint>
#include <mutex>
#include "json_lib/json.hpp"

namespace fuzzing {

// Preferable to enum because not convertible to int (we dont want them to act like int)
// Do not cause name clashing by exporting their enum to surrounding scope
// --> they have aspects of classes (scoped members and absence of conversions)
enum class MMIO_action {
    None,
    NotifySimEnd,
    ApplyMask,
    StartInjection,
    NotifyInitEnd
};


struct MMIO_register 
{
    std::string                          peripheral;        // Name of the peripheral
    std::string                          name;              // Name of the register
    uint32_t                             address;           // Full address of the register (not offset)
    uint32_t                             length;     
    std::optional<uint32_t>              mask;              // Optional mask to overwrite/modify software values
    std::optional<double>                interval_ms;       // Injection interval
    bool                                 has_handler;       // true if an handler has already been registered
    bool                                 ready_to_receive;  // true when the peripheral is ready to receive data --> should be configurable, now ready at the first access
    std::shared_ptr<std::queue<uint8_t>> data_queue;        // shared fuzzing data across registers
    std::optional<MMIO_action>           on_write;          // action to take on write

    MMIO_register(std::string peripheral_, std::string name_, uint32_t address_, uint32_t length_, std::optional<uint32_t> mask_, std::optional<double> injection_interval, MMIO_action action)
        : peripheral(std::move(peripheral_)),
            name(std::move(name_)),
            address(address_),
            length(length_),
            mask(mask_),
            interval_ms(injection_interval),
            has_handler(false),
            ready_to_receive(false),
            data_queue(std::make_shared<std::queue<uint8_t>>()),
            on_write(action) {
    }

    /* This method applies the mask according to the value in the json file */
    void apply_mask(uint8_t* data_ptr, uint8_t tlm_len){
        if (!mask.has_value()) return;

        int data_len = std::min<int>(tlm_len, length);

        uint32_t mmio_data = 0;
        memcpy(&mmio_data, data_ptr, data_len);   // load bytes

        mmio_data &= mask.value();                // apply mask

        memcpy(data_ptr, &mmio_data, data_len);   // store bytes
    }


    void set_ready_to_receive(){
        ready_to_receive = true;
    }

    bool is_ready_to_receive(){
        return ready_to_receive;
    }

    void set_has_handler(){
        has_handler = true;
    }

    bool start_injection(){
        return (ready_to_receive && !has_handler);
    }

};


class MMIO_register_file
{
    using json = nlohmann::json;

    public:
        MMIO_register_file();

        MMIO_register* find(uint32_t addr);

        // This method accepts a function that acts on the regs saved in the address map
        template <typename F>
        void for_each(F&& f) { // && is a forwarding reference
            for (auto& [_, reg] : address_map)     // // is means that this function (for_each) can accept a temporary (aka rvalue) object
                f(reg);
        }

    private:
        std::string json_cfg_path;
        std::unordered_map<uint32_t, MMIO_register> address_map;  // Fast lookups, insertions, deletions --> O(1)

        // These methods parse the json file and the fields of the registers defined in it
        void load_json_config();
        void parse_mmio_regs(const json &j, const std::string &peripheral_name);
};


} // namespace fuzzing

#endif // !REG_FILE_HPP