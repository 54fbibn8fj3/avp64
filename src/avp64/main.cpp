/******************************************************************************
 *                                                                            *
 * Copyright 2024 Lukas Jünger, Nils Bosbach                                  *
 *                                                                            *
 * This software is licensed under the MIT license found in the               *
 * LICENSE file at the root directory of this source tree.                    *
 *                                                                            *
 ******************************************************************************/

#include "avp64/system.hpp"
#include "fuzzing/fuzzing_logger.hpp"

extern "C" int sc_main(int argc, char** argv) {
    auto logger = std::make_shared<fuzzing::FuzzLogger>();
    testing::set_global_logger(logger);

    avp64::system system("system");
    system.parse_args(argc, argv);
    return system.run();
}
