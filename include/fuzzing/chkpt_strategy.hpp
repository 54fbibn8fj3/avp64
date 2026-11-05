#pragma once
#include "init_config.hpp"
#include "vp_test/types.hpp"
#include "fuzzing/mmio_probe.hpp"
#include <condition_variable>
#include <mutex>
#include <atomic>
#include <semaphore.h>

namespace fuzzing {

class ICheckpointStrategy {
    public:
        virtual testing::status unblocking_checkpoint() = 0;
        virtual testing::status blocking_checkpoint() = 0;
        virtual void notify_do_run() = 0;
        virtual void at_exit(mwr::u64 exit_code) = 0;
        virtual void register_exit_handler(std::function<void(mwr::u64)> func) = 0;
        virtual void register_fill_covshm(std::function<void()> func) = 0;
        virtual ~ICheckpointStrategy() = default;
};

class ForkCheckpoint : public ICheckpointStrategy{
    public:
        ForkCheckpoint(MMIOprobe& probe);
        void at_exit(mwr::u64 exit_code) override;
        testing::status unblocking_checkpoint() override;
        testing::status blocking_checkpoint() override;
        void notify_do_run() override;
        void register_exit_handler(std::function<void(mwr::u64)> func) override;
        void register_fill_covshm(std::function<void()> func) override;

        ~ForkCheckpoint();

    private:
        MMIOprobe&                    probe;
        // std::mutex                    mtx;
        // std::condition_variable       cv;
        sem_t sem;
        std::atomic_bool              fork_loop_exist;
        std::function<void(mwr::u64)> notify_exit_request;
        std::function<void()>         fill_cov_shm;
        
        void fork_chkpt();
};

class CriuCheckpoint : public ICheckpointStrategy{
    public:
        CriuCheckpoint(MMIOprobe& mmio_probe);
        void at_exit(mwr::u64 exit_code) override;
        testing::status unblocking_checkpoint() override;
        testing::status blocking_checkpoint() override;
        void notify_do_run() override;
        void register_exit_handler(std::function<void(mwr::u64)> func) override;
        void register_fill_covshm(std::function<void()> func) override;

    private:
        MMIOprobe& probe;
        sem_t sem;
        std::function<void(mwr::u64)> notify_exit_request;
        std::function<void()>         fill_cov_shm;

        enum LOG_LVL {
            LOG_MSG = 0,   // Print messages regardless of log level
            LOG_ERROR = 1, // Errors only
            LOG_WARN = 2,  // Warnings
            LOG_INFO = 3,  // Informative
            LOG_DEBUG = 4  // Debug only
        };
        
        bool snapshot_exists;
        std::string m_socket_path;
        enum LOG_LVL m_log_lvl;
        std::string m_log_file_path;
        std::string m_img_dir;
        int m_img_dir_fd;
        bool m_initialized;

        pid_t get_tracer_pid(pid_t pid); 
        void snapshot_init();
        void take_snapshot();
        void save_checkpoint_pid(pid_t sim_pid);
        bool is_error(const int retval) const;
};

class HybridCheckpoint : public ICheckpointStrategy{
    public:
        HybridCheckpoint(MMIOprobe& mmio_probe);
        void at_exit(mwr::u64 exit_code) override;
        testing::status unblocking_checkpoint() override;
        testing::status blocking_checkpoint() override;
        void notify_do_run() override;
        void register_exit_handler(std::function<void(mwr::u64)> func) override;
        void register_fill_covshm(std::function<void()> func) override;

        ~HybridCheckpoint();

    private:
        MMIOprobe& probe;
        sem_t sem;
        std::atomic_bool              fork_loop_exist;
        std::function<void(mwr::u64)> notify_exit_request;
        std::function<void()>         fill_cov_shm;

        enum LOG_LVL {
            LOG_MSG = 0,   // Print messages regardless of log level
            LOG_ERROR = 1, // Errors only
            LOG_WARN = 2,  // Warnings
            LOG_INFO = 3,  // Informative
            LOG_DEBUG = 4  // Debug only
        };
        
        bool snapshot_exists;
        std::string m_socket_path;
        enum LOG_LVL m_log_lvl;
        std::string m_log_file_path;
        std::string m_img_dir;
        int m_img_dir_fd;
        bool m_initialized;

        pid_t get_tracer_pid(pid_t pid); 
        void snapshot_init();
        void take_snapshot();
        void fork_chkpt();
        void save_checkpoint_pid(pid_t sim_pid);
        bool is_error(const int retval) const;
};

}