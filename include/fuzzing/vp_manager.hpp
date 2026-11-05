#ifndef VP_MANAGER_HPP
#define VP_MANAGER_HPP

#include "fuzzing/mmio_probe.hpp"
#include "vp_test/types.hpp"
#include "fuzzing/init_config.hpp"
#include "fuzzing/chkpt_strategy.hpp"
#include "vcml/core/types.h"
#include "vcml/debugging/subscriber.h"
#include "vcml/debugging/suspender.h"
#include "vcml/debugging/target.h"

#include <fcntl.h>
#include <mqueue.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <atomic>
#include <optional>
#include <cstdint>
#include <string>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <algorithm>


namespace fuzzing {

// DO NOT replace these with #define and DO NOT use macros in the future
// Macros leak to files that include this header and might generate collisions
// Macros also ignores types & are impossible to debug
//constexpr size_t MAP_SIZE_POW2 = 16;
constexpr size_t MAP_SIZE_POW2 = 21;
constexpr size_t MAP_SIZE = 1ull << MAP_SIZE_POW2;
constexpr int64_t timeout_s = 129060;

enum CHKPT_MODE : int {
    NO_CHKPT, 
    CRIU,
    FORK,
    HYBRID   
};

enum class SimEvent {
    None,
    Breakpoint,
    Exit,
    Checkpoint,
    Timeout
  };

struct brkpt {
  std::string   name;
  std::uint64_t addr;

  // if the string is empty it gives true (vacuous truth)
  // It is const because it does not modify the object
  bool is_null() const {  
    return std::all_of(name.begin(), name.end(),
                        [](char c) { return c == '\0' || c == ' '; });
  }
};


class VPManager final : public vcml::debugging::suspender, public vcml::debugging::subscriber {
  public:
    explicit VPManager(const std::string &name, MMIOprobe &get_probe,
                        vcml::debugging::target &core);

    void on_complete_init();

    void suspend_simulation();

    void resume_simulation();

    void enable_mmio_tracking();

    void enable_code_coverage();

    testing::status get_ret_val(uint64_t &val);

    testing::status wait_for_event();

    testing::status run_init(InitConfig& cfg);

    testing::status run_simulation();

    uint8_t *get_cov_array();

    void init_shm(uint32_t cov_id, uint32_t input_id, int offset);

    void notify_breakpoint_hit(const vcml::debugging::breakpoint &bp, const sc_core::sc_time& t) override;

    void notify_basic_block(vcml::debugging::target &tgt, mwr::u64 pc, size_t blksz,
                            size_t offset, const sc_core::sc_time& t) override;

    ~VPManager();

 private:
  // ---- Dependencies ----
  MMIOprobe &mmio_probe;
  vcml::debugging::target &target_core;

  // ---- Sim state ----
  std::atomic_bool        is_breakpoint_hit;
  bool                    is_sim_suspended;
  std::optional<SimEvent> current_event;
  std::mutex              mtx;
  std::condition_variable cv;

  bool set_breakpoint(brkpt &bp);
  void handle_exit_request(mwr::u64 exit_code);

  // ---- Checkpoint ----
  std::unique_ptr<ICheckpointStrategy> checkpoint;
  void set_checkpoint_mode();

  // ---- Configuration ----
  brkpt       start_breakpoint;
  brkpt       end_breakpoint;
  std::string ret_register;
  std::string run_mode;
  brkpt       error_symbol;

  // ---- Cov shm ----
  uint8_t  bb_array[MAP_SIZE];
  uint64_t prev_bb_loc;
  uint8_t* cov_shm;
  uint32_t cov_shm_id;

  testing::status write_shm_cov(int shm_cov_id);
  bool attach_cov_shm(int shm_cov_id);

  // ---- Ret value ----
  std::optional<uint64_t> ret_value;
  std::pair<bool, vcml::u64> read_reg_value(std::string &reg_name);
};
}  // namespace fuzzing

#endif
