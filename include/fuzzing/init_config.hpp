#pragma once

#include <array>
#include <string>
#include <cstdint>

namespace fuzzing {

constexpr std::size_t NUM_SYMBOLS = 5;

struct InitConfig {
    uint32_t input_shm_id;
    uint32_t input_shm_offset;
    uint32_t cov_shm_id;
    uint32_t cov_shm_offset;
    std::array<std::string, NUM_SYMBOLS> symbols;
};

}