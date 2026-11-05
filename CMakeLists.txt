##############################################################################
#                                                                            #
# Copyright 2024 Lukas Jünger, Nils Bosbach                                  #
#                                                                            #
# This software is licensed under the MIT license.                           #
# A copy of the license can be found in the LICENSE file at the root         #
# of the source tree.                                                        #
#                                                                            #
##############################################################################

cmake_minimum_required(VERSION 3.12)
project(avp64 VERSION 2024.08.02 LANGUAGES C CXX)

option(AVP64_BUILD_TESTS "Build unit tests" OFF)
option(AVP64_BUILD_RUNNER "Build avp64 runner" ON)
set(AVP64_LINTER "" CACHE STRING "Code linter to use")

include(cmake/common.cmake)

find_github_repo(vcml "machineware-gmbh/vcml")
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
find_package(LibCRIU REQUIRED)


set(OCX_QEMU_ARM_BUILD_TESTS OFF CACHE BOOL "disable ocx tests")
find_github_repo(ocx-qemu-arm "snps-virtualprototyping/ocx-qemu-arm")

find_package(vp-testing-interface  REQUIRED CONFIG)

set(src "${CMAKE_CURRENT_SOURCE_DIR}/src")
set(inc "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(gen ${CMAKE_CURRENT_BINARY_DIR}/gen)

configure_file(${src}/avp64/version.h.in
    ${gen}/avp64/version.h @ONLY)

set(sources
    ${src}/avp64/core.cpp
    ${src}/avp64/cpu.cpp
    ${src}/fuzzing/criu_chkpt.cpp
    ${src}/fuzzing/hybrid_chkpt.cpp
    ${src}/fuzzing/fork_chkpt.cpp
    ${src}/fuzzing/receiver.cpp
    ${src}/fuzzing/vp_manager.cpp
    ${src}/fuzzing/mmio_probe.cpp
    ${src}/fuzzing/fuzzing_logger.cpp
    ${src}/fuzzing/uart_injector.cpp
    ${src}/fuzzing/can_injector.cpp
    ${src}/fuzzing/i2c_injector.cpp
    ${src}/fuzzing/nrf51_twi.cpp
    ${src}/fuzzing/mmio_register_file.cpp
    ${src}/fuzzing/chkpt.cpp
)

add_library(avp64 STATIC ${sources})

target_compile_options(avp64 PRIVATE ${MWR_COMPILER_WARN_FLAGS})
target_include_directories(avp64 PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/external)
target_include_directories(avp64 PUBLIC ${inc})
target_include_directories(avp64 PUBLIC ${gen})
target_include_directories(avp64 PUBLIC ${OCX_QEMU_ARM_HOME}/ocx/include)
target_include_directories(avp64 PUBLIC ${LIBCRIU_INCLUDE_DIRS})

target_link_libraries(avp64 PUBLIC ${CMAKE_DL_LIBS})
target_link_libraries(avp64 PUBLIC
  vcml
  ${LIBCRIU_LIBRARIES}
  vp-testing-interface::vp-testing-interface)
set_target_properties(avp64 PROPERTIES CXX_STANDARD 17)
set_target_properties(avp64 PROPERTIES CXX_CLANG_TIDY "${AVP64_LINTER}")
set_target_properties(avp64 PROPERTIES VERSION "${AVP64_VERSION}")
set_target_properties(avp64 PROPERTIES SOVERSION "${AVP64_VERSION_MAJOR}")

if(NOT ${AVP64_LINTER} STREQUAL "")
  # -std=c++17 is not passed to the compiler if it is the comiler's default
  # this caused problems with clang-tidy
  set_target_properties(avp64 PROPERTIES CXX_STANDARD_REQUIRED ON)
endif()

set_target_properties(ocx-qemu-arm PROPERTIES EXCLUDE_FROM_ALL FALSE)

install(TARGETS avp64)
install(TARGETS ocx-qemu-arm DESTINATION lib)
install(DIRECTORY sw/ DESTINATION sw)
install(DIRECTORY ${inc}/ DESTINATION include)
install(DIRECTORY ${gen}/ DESTINATION include)

if(AVP64_BUILD_TESTS)
  message(STATUS "Building AVP64 tests")
  enable_testing()
  add_subdirectory(tests)
endif()

if(AVP64_BUILD_RUNNER)
  add_executable(avp64-runner
        ${src}/avp64/system.cpp
        ${src}/avp64/main.cpp
  )

  if (LIBCRIU_FOUND)
    target_compile_definitions(avp64 PUBLIC HAVE_LIBCRIU=1)
    target_compile_definitions(avp64-runner PUBLIC HAVE_LIBCRIU=1)
  endif()

  target_compile_options(avp64-runner PRIVATE ${MWR_COMPILER_WARN_FLAGS})
  target_include_directories(avp64-runner PRIVATE ${src})
  target_include_directories(avp64-runner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/external)
  set_target_properties(avp64-runner PROPERTIES CXX_STANDARD 17)
  set_target_properties(avp64-runner PROPERTIES CXX_CLANG_TIDY "${AVP64_LINTER}")
  set_target_properties(avp64-runner PROPERTIES VERSION "${AVP64_VERSION}")
  set_target_properties(avp64-runner PROPERTIES SOVERSION "${AVP64_VERSION_MAJOR}")
  target_link_whole_archives(avp64-runner avp64
    vcml
    ${LIBCRIU_LIBRARIES}
    vp-testing-interface::vp-testing-interface)

  if(NOT ${AVP64_LINTER} STREQUAL "")
    # -std=c++17 is not passed to the compiler if it is the comiler's default
    # this caused problems with clang-tidy
    set_target_properties(avp64-runner PROPERTIES CXX_STANDARD_REQUIRED ON)
  endif()

  install(TARGETS avp64-runner)
endif()
