#include "fuzzing/fuzzing_logger.hpp"
#include "fuzzing/mmio_register_file.hpp"

namespace fuzzing{

MMIO_register_file::MMIO_register_file():
json_cfg_path("")
{
    const char* env_var = getenv("JSON_CFG_PATH");
    json_cfg_path = (env_var != nullptr) ? std::string(env_var) : "";

    if(!json_cfg_path.empty())
        load_json_config();
    else 
        VCML_ERROR("Failed to find mmio_config.json, is JSON_CFG_PATH set?");
}


void MMIO_register_file::load_json_config()
{
    log_info_message("load_json_config");

    std::ifstream file(json_cfg_path);
    if (!file.is_open()) {
        VCML_ERROR("Failed to open mmio_config.json");
        return;
    }

    json config;
    try {
        file >> config;
    } catch (const json::parse_error& e) {
        VCML_ERROR("json parse error");
        return;
    }

    // ++it avoids copying 
    for( auto it = config.begin(); it != config.end(); ++it)
      parse_mmio_regs(config, it.key());
}


// This function iterates over the reg fields in the json, fills the register
// object and the address map
void MMIO_register_file::parse_mmio_regs(const json        &j,
                                const std::string &peripheral_name) {
  log_info_message("Parsing the json file");
  const auto &registers =
      j[peripheral_name]["registers"];  // dont remove &, json can be huge, it
                                        // creates a read-only reference

  for (auto file_it = registers.begin(); file_it != registers.end(); ++file_it) {
    const std::string &name = file_it.key();
    const auto        &reg  = file_it.value();  // Remaining of the json associated to the reg

    uint32_t addr = 0;
    uint32_t len = 0;
    std::optional<uint32_t> mask = std::nullopt;
    std::optional<double> interval_ms = std::nullopt;
    MMIO_action action = MMIO_action::None;

    // 1. Extract the address from the json as a string 
    // 2. Convert the string to an unsigned long* using hex (base 16) 
    // *other (unfit) options: int, stoull
    auto it = reg.find("address");
    if (it != reg.end() && !it->is_null()) 
        addr = std::stoul(it->get<std::string>(), nullptr, 16);
    else
        log_error_message("No address given for register: %s", name.c_str());

    it = reg.find("length");
    if (it != reg.end() && !it->is_null()) 
        len = it->get<uint32_t>();
    else
        log_error_message("No length given for register: %s", name.c_str());

    it = reg.find("mask");
    if (it != reg.end() && !it->is_null()) 
        mask = std::stoul(it->get<std::string>(), nullptr, 16);

    it = reg.find("interval_ms");
    if (it != reg.end() && !it->is_null()) 
        interval_ms = std::stod(it->get<std::string>());


    it = reg.find("on_write");
    if (it != reg.end() && !it->is_null()) {
        std::optional<std::string> s = it->get<std::string>();
        if(s.value() == "notify_sim_end")
            action = MMIO_action::NotifySimEnd;
        else if(s.value() == "apply_mask")
            action = MMIO_action::ApplyMask;
        else if(s.value() == "start_injection")
            action = MMIO_action::StartInjection;
        else if(s.value() == "notify_init_end")
            action = MMIO_action::NotifyInitEnd;
        else
            log_error_message("No action named: %s", s.value().c_str());
    }

    address_map.emplace(addr, MMIO_register{peripheral_name, name, addr, len, mask, interval_ms, action});
  }
}


MMIO_register* MMIO_register_file::find(uint32_t addr) 
{
    //log_info_message("MMIO_register_file::find");

    auto it = address_map.find(addr);
    return (it != address_map.end()) ? &it->second : nullptr;
}

} // namespace fuzzing
