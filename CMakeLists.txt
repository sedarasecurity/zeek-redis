cmake_minimum_required(VERSION 3.0)

project(ZeekPluginRedis)

if ( NOT ZEEK_DIST )
    message(FATAL ERROR "ZEEK_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH})

include(ZeekPlugin)

find_package(LibHIREDIS)
find_package(LibREDISPLUSPLUS)

if (NOT LIBHIREDIS_FOUND)
  message(STATUS "LibHIREDIS ROOT DIR : ${LibHIREDIS_ROOT_DIR}")
  message(STATUS "LibHIREDIS INC DIR  : ${LibHIREDIS_INCLUDE_DIR}")
  message(STATUS "LibHIREDIS LIB DIR  : ${LibHIREDIS_LIBRARIES}")
  message(FATAL_ERROR "LibHIREDIS not found.")
endif()

if (LibHIREDIS_VERSION)
    if(LibHIREDIS_VERSION VERSION_LESS "0.12.1")
        message(FATAL_ERROR "LibHIREDIS must be 0.12.1 or greater")
    endif()
else()
    message(WARNING "Unable to determine LibHIREDIS library version")
endif()

if (NOT LIBREDISPLUSPLUS_FOUND)
  message(STATUS "LibREDISPLUSPLUS ROOT DIR  : ${LibREDISPLUSPLUS_ROOT_DIR}")
  message(STATUS "LibREDISPLUSPLUS INC DIR   : ${LibREDISPLUSPLUS_INCLUDE_DIR}")
  message(STATUS "LibREDISPLUSPLUS LIB DIR   : ${LibREDISPLUSPLUS_LIBRARIES}")
  message(FATAL_ERROR "LibREDISPLUSPLUS not found.")
endif()

message(STATUS "---------------------")
message(STATUS "LibREDISPLUSPLUS ROOT DIR  : ${LibREDISPLUSPLUS_ROOT_DIR}")
message(STATUS "LibREDISPLUSPLUS INC DIR   : ${LibREDISPLUSPLUS_INCLUDE_DIR}")
message(STATUS "LibREDISPLUSPLUS LIB DIR   : ${LibREDISPLUSPLUS_LIBRARIES}")
message(STATUS "---------------------")
message(STATUS "LibHIREDIS ROOT DIR : ${LibHIREDIS_ROOT_DIR}")
message(STATUS "LibHIREDIS INC DIR  : ${LibHIREDIS_INCLUDE_DIR}")
message(STATUS "LibHIREDIS LIB DIR  : ${LibHIREDIS_LIBRARIES}")

include_directories(BEFORE ${LibHIREDIS_INCLUDE_DIR})
zeek_plugin_begin(sedara Redis)

include_directories(BEFORE ${LibREDISPLUSPLUS_INCLUDE_DIR})
zeek_plugin_link_library(${LibREDISPLUSPLUS_LIBRARIES})

zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/RedisWriter.cc)
zeek_plugin_bif(src/redis.bif)
zeek_plugin_dist_files(COPYING LICENSE README README.md VERSION)
zeek_plugin_link_library(${LibHIREDIS_LIBRARIES})
zeek_plugin_link_library(${LibREDISPLUSPLUS_LIBRARIES})
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
