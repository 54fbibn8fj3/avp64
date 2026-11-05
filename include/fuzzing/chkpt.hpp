#ifndef CHKPT_H
#define CHKPT_H

#include <string>
#include "vcml/core/types.h"
#include "vcml/core/systemc.h"
#include "vcml/core/peripheral.h"
#include "vcml/core/model.h"

#include "vcml/protocols/tlm.h"

namespace fuzzing {
namespace checkpoint {

enum CHKPT_MODE : int {
    NO_CHKPT,
    CRIU,
    FORK   
};

class chkpt : public vcml::peripheral
{
    public:
        enum LOG_LVL {
            LOG_MSG = 0,   // Print messages regardless of log level
            LOG_ERROR = 1, // Errors only
            LOG_WARN = 2,  // Warnings
            LOG_INFO = 3,  // Informative
            LOG_DEBUG = 4  // Debug only
        };

        chkpt(const sc_core::sc_module_name& nm);

        void checkpoint();
        void set_notify_chkpt_end_cb(std::function<void()> cb);

        // Is this useful?
        const std::string& get_img_dir() const;

        vcml::reg<vcml::u32> start;
        vcml::reg<vcml::u32> waitc; //not sure we need this, criu should freeze the process!


        vcml::tlm_target_socket in;
        //VCML_KIND(chkpt);
        virtual void reset() override;
        virtual ~chkpt();
    private:

        std::string m_socket_path;
        enum LOG_LVL m_log_lvl;
        std::string m_log_file_path;
        std::string m_img_dir;
        int m_img_dir_fd;
        bool m_initialized;
        const char *tc_chkpt_mode;
        int chkpt_mode;

        // Set callbacks to suspend the execution since we dont have the rights :)
        std::function<void()> notify_chkpt_end_cb;

        void write_start(vcml::u32 val);

        bool is_error(int retval) const;
        void init();
};

} // namespace checkpoint
} // namespace fuzzing

#endif
