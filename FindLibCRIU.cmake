find_package(PkgConfig QUIET)
pkg_check_modules(PKGCFG_LIBCRIU QUIET criu)

find_path(LIBCRIU_INCLUDE_DIRS
    NAMES criu.h
    HINTS /usr/local/include/criu
)

# For library
find_library(LIBCRIU_LIBRARIES
    NAMES criu
    HINTS /usr/local/lib/x86_64-linux-gnu
)


# If only singular form is found, define plural as an alias
if (LIBCRIU_INCLUDE_DIR AND NOT LIBCRIU_INCLUDE_DIRS)
    set(LIBCRIU_INCLUDE_DIRS ${LIBCRIU_INCLUDE_DIR})
endif ()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibCRIU
    REQUIRED_VARS LIBCRIU_INCLUDE_DIRS LIBCRIU_LIBRARIES)

mark_as_advanced(LIBCRIU_INCLUDE_DIRS LIBCRIU_LIBRARIES)

message(DEBUG "LIBCRIU_FOUND        " ${LIBCRIU_FOUND})
message(DEBUG "LIBCRIU_INCLUDE_DIRS " ${LIBCRIU_INCLUDE_DIRS})
message(DEBUG "LIBCRIU_LIBRARIES    " ${LIBCRIU_LIBRARIES})
