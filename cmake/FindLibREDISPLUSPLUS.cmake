# - Try to find LibREDISPLUSPLUS headers and libraries.
#
# Usage of this module as follows:
#
#     find_package(LibREDISPLUSPLUS)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  LibREDISPLUSPLUS_ROOT_DIR  Set this variable to the root installation of
#                      LibREDISPLUSPLUS if the module has problems finding
#                      the proper installation path.
#
# Variables defined by this module:
#
#  LIBREDISPLUSPLUS_FOUND              System has LibREDISPLUSPLUS libs/headers
#  LibREDISPLUSPLUS_LIBRARIES          The LibREDISPLUSPLUS libraries
#  LibREDISPLUSPLUS_INCLUDE_DIR        The location of LibREDISPLUSPLUS headers

find_path(LibREDISPLUSPLUS_ROOT_DIR
    NAMES include/sw/redis++/redis++.h
)

find_library(LibREDISPLUSPLUS_LIBRARIES
    NAMES libredis++ redis++
    HINTS ${LibREDISPLUSPLUS_ROOT_DIR}/lib
    PATH_SUFFIXES ${CMAKE_LIBRARY_ARCHITECTURE}
)

find_path(LibREDISPLUSPLUS_INCLUDE_DIR
    NAMES sw/redis++/redis++.h
    HINTS ${LibREDISPLUSPLUS_ROOT_DIR}/include
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
    LibREDISPLUSPLUS DEFAULT_MSG
    LibREDISPLUSPLUS_LIBRARIES
    LibREDISPLUSPLUS_INCLUDE_DIR
)

mark_as_advanced(
    LibREDISPLUSPLUS_ROOT_DIR
    LibREDISPLUSPLUS_LIBRARIES
    LibREDISPLUSPLUS_INCLUDE_DIR
)