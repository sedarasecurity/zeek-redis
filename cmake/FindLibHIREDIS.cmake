# - Try to find LibHIREDIS headers and libraries.
#
# Usage of this module as follows:
#
#     find_package(LibHIREDIS)
#
# Variables used by this module, they can change the default behaviour and need
# to be set before calling find_package:
#
#  LibHIREDIS_ROOT_DIR  Set this variable to the root installation of
#                      LibHIREDIS if the module has problems finding
#                      the proper installation path.
#
# Variables defined by this module:
#
#  LIBHIREDIS_FOUND              System has LibHIREDIS libs/headers
#  LibHIREDIS_LIBRARIES          The LibHIREDIS libraries
#  LibHIREDIS_INCLUDE_DIR        The location of LibHIREDIS headers

find_path(LibHIREDIS_ROOT_DIR
    NAMES include/hiredis/hiredis.h
)

find_library(LibHIREDIS_LIBRARIES
    NAMES hiredis
    HINTS ${LibHIREDIS_ROOT_DIR}/lib
    PATH_SUFFIXES ${CMAKE_LIBRARY_ARCHITECTURE}
)

find_path(LibHIREDIS_INCLUDE_DIR
    NAMES hiredis.h
    HINTS ${LibHIREDIS_ROOT_DIR}/include/hiredis
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibHIREDIS DEFAULT_MSG
    LibHIREDIS_LIBRARIES
    LibHIREDIS_INCLUDE_DIR
)

mark_as_advanced(
    LibHIREDIS_ROOT_DIR
    LibHIREDIS_LIBRARIES
    LibHIREDIS_INCLUDE_DIR
)
