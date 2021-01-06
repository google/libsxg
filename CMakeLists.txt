# Copyright 2019 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

project (sxg LANGUAGES C CXX)

set (CMAKE_PROJECT_VERSION "0")
set (CMAKE_PROJECT_VERSION_MAJOR "0")
set (CMAKE_PROJECT_VERSION_MINOR "2")
set (CMAKE_PROJECT_VERSION_PATCH "0")

set (LIBSXG_CORE_VERSION
     "${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}")
set (LIBSXG_SOVERSION "${CMAKE_PROJECT_VERSION_MAJOR}")

option (SXG_BUILD_SHARED "Build shared library" ON)
option (SXG_BUILD_STATIC "Build static libirary" OFF)
option (SXG_BUILD_EXECUTABLES "Build gensxg/gencertchain executables" ON)

if (NOT SXG_BUILD_SHARED AND NOT SXG_BUILD_STATIC)
  message(
    FATAL_ERROR
    "One of SXG_BUILD_SHARED or SXG_BUILD_STATIC is required" )
endif ()

if (NOT SXG_BUILD_SHARED AND SXG_BUILD_EXECUTABLES)
  message(
    FATAL_ERROR
    "Shared library required for gensxg/gencertchain executables" )
endif ()

option (
  RUN_TEST
  "If false, build libsxg without building tests.\
  Building tests of libsxg requires more recent version of cmake (>= 3.13).\
  Tests include fuzzer will be disabled automatically if it is not supported
  by the compiler."
  TRUE)

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE "Debug")
endif ()

if (RUN_TEST)
  # `target_link_options` used in fuzzing test requires 3.13
  cmake_minimum_required (VERSION 3.13)
else ()
  cmake_minimum_required (VERSION 3.0)
endif ()

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -std=c++11 -fPIC")
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -std=c99 -fPIC")

set (CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb")
set (CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb")

include (ExternalProject)
set_property (DIRECTORY ${PROJECT_SOURCE_DIR} PROPERTY EP_UPDATE_DISCONNECTED 1)

find_package (OpenSSL REQUIRED)

set (SXG_SOURCES
  src/sxg_buffer.c
  src/sxg_buffer_debug.c
  src/sxg_cbor.c
  src/sxg_cert_chain.c
  src/sxg_codec.c
  src/sxg_encoded_response.c
  src/sxg_generate.c
  src/sxg_header.c
  src/sxg_raw_response.c
  src/sxg_sig.c
  src/sxg_signer_list.c)

if (SXG_BUILD_SHARED)
  add_library (sxg SHARED ${SXG_SOURCES})

  target_include_directories (sxg PRIVATE ${PROJECT_SOURCE_DIR}/include
                                          ${OPENSSL_INCLUDE_DIR})

  target_link_libraries (sxg PRIVATE ${OPENSSL_LIBRARIES})
endif()

if (SXG_BUILD_STATIC)
  add_library (sxg_static STATIC ${SXG_SOURCES})
  set_target_properties(sxg_static PROPERTIES OUTPUT_NAME sxg)

  target_include_directories (sxg_static PRIVATE ${PROJECT_SOURCE_DIR}/include
                                                 ${OPENSSL_INCLUDE_DIR})

  target_link_libraries (sxg_static PRIVATE ${OPENSSL_LIBRARIES})
endif ()

if (SXG_BUILD_EXECUTABLES)
  add_executable (gensxg src/gensxg.c)

  target_include_directories (gensxg PRIVATE ${PROJECT_SOURCE_DIR}/include
                                             ${OPENSSL_INCLUDE_DIR})

  target_link_libraries (gensxg PRIVATE ${OPENSSL_LIBRARIES} sxg)

  add_executable (gencertchain src/gencertchain.c)

  target_include_directories (gencertchain PRIVATE ${PROJECT_SOURCE_DIR}/include
                                                 ${OPENSSL_INCLUDE_DIR})

  target_link_libraries (gencertchain PRIVATE ${OPENSSL_LIBRARIES} sxg)
endif ()

# ##############################################################################
# Installing
# ##############################################################################

if (SXG_BUILD_SHARED)
  set_target_properties (
    sxg PROPERTIES VERSION ${LIBSXG_CORE_VERSION} SOVERSION ${LIBSXG_SOVERSION})

  set_target_properties (sxg PROPERTIES PUBLIC_HEADER "${HEADERS}")
  install (
    TARGETS sxg
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT library)
endif ()
if (SXG_BUILD_STATIC)
  set_target_properties (
    sxg_static PROPERTIES VERSION ${LIBSXG_CORE_VERSION} SOVERSION ${LIBSXG_SOVERSION})

  set_target_properties (sxg_static PROPERTIES PUBLIC_HEADER "${HEADERS}")
  install (
    TARGETS sxg_static
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT library)
endif ()

install (
  DIRECTORY ${CMAKE_SOURCE_DIR}/include/ PUBLIC_HEADER
  DESTINATION ${CMAKE_INSTALL_PREFIX}/include
  FILES_MATCHING
  PATTERN "*.h*")

if (SXG_BUILD_EXECUTABLES)
  install (TARGETS gensxg RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  install (TARGETS gencertchain RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif ()

# ##############################################################################
# Generate man files
# ##############################################################################

# This target requires ronn executable in your path.
add_custom_target (
  man
  COMMAND ronn -r ${CMAKE_SOURCE_DIR}/docs/gencertchain.md --pipe > ${CMAKE_SOURCE_DIR}/docs/gencertchain.1 &&
          ronn -r ${CMAKE_SOURCE_DIR}/docs/gensxg.md --pipe > ${CMAKE_SOURCE_DIR}/docs/gensxg.1 &&
          ronn -r ${CMAKE_SOURCE_DIR}/docs/libsxg.md --pipe > ${CMAKE_SOURCE_DIR}/docs/libsxg.3
  COMMENT "Generating roff files with ronn ...")

# ##############################################################################
# Linter
# ##############################################################################

# This target requires cmake-format executable in your path.
add_custom_target (
  cmake_format
  COMMAND cmake-format -i ${CMAKE_SOURCE_DIR}/CMakeLists.txt
  COMMENT "Formating with cmake-format ...")

# This target requires clang-format executable in your path.
add_custom_target (
  clang_format
  COMMAND
    cd ${CMAKE_SOURCE_DIR} && git ls-files *.{c,h,hpp,cpp,cc} | xargs
    clang-format -style=file -i
  COMMENT "Formating with clang-format ...")

# This target requires [markdownlint](https://github.com/igorshubovych/markdownlint-cli) executable in your path.
add_custom_target (
  man_format
  COMMAND
    find ${CMAKE_SOURCE_DIR}/docs/ -name '*.md' | xargs markdownlint -c ${CMAKE_SOURCE_DIR}/.markdownlint
  COMMENT "Formating with markdownlint ...")

# ##############################################################################
# Testing
# ##############################################################################
if (RUN_TEST)
  enable_testing ()

  file (COPY tests/testdata DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

  ExternalProject_Add (
    gtest
    GIT_REPOSITORY https://github.com/google/googletest
    GIT_TAG master
    SOURCE_DIR ${PROJECT_BINARY_DIR}/third_party/gtest
    BINARY_DIR ${PROJECT_BINARY_DIR}/gtest
    INSTALL_COMMAND "")
  add_library (libgtest IMPORTED STATIC GLOBAL)
  add_dependencies (libgtest gtest)
  set_target_properties (
    libgtest
    PROPERTIES "IMPORTED_LOCATION" "${PROJECT_BINARY_DIR}/gtest/lib/libgtest.a"

               "IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}")
  add_library (libgtest_main IMPORTED STATIC GLOBAL)
  add_dependencies (libgtest_main gtest)
  set_target_properties (
    libgtest_main
    PROPERTIES "IMPORTED_LOCATION"
               "${PROJECT_BINARY_DIR}/gtest/lib/libgtest_main.a"
               "IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}")
  set (GTEST_INCLUDE
       "${PROJECT_BINARY_DIR}/third_party/gtest/googletest/include")
  if (SXG_BUILD_SHARED)
    add_library (test_util SHARED tests/test_util.cc)
  else ()
    add_library (test_util STATIC tests/test_util.cc)
  endif ()
  target_include_directories (test_util PUBLIC ${PROJECT_SOURCE_DIR}/include
                                               ${GTEST_INCLUDE})
  if (SXG_BUILD_SHARED)
    add_dependencies (test_util gtest libgtest libgtest_main sxg)
    target_link_libraries (test_util INTERFACE libgtest libgtest_main pthread sxg
                                              ${OPENSSL_LIBRARIES})
  else ()
    add_dependencies (test_util gtest libgtest libgtest_main sxg_static)
    target_link_libraries (test_util INTERFACE libgtest libgtest_main pthread sxg_static
                                              ${OPENSSL_LIBRARIES})
  endif ()
endif ()

set (SANITIZER_OPTIONS "-fsanitize=address,leak,undefined")
macro (add_test_macro target_name test_name with_sanitizer)
  add_executable (${target_name} tests/${test_name}.cc)
  add_test (NAME ${target_name} COMMAND ${target_name})
  add_dependencies (${target_name} test_util)
  target_link_libraries (${target_name} PRIVATE test_util)
  if (with_sanitizer)
    target_compile_options (${target_name} PRIVATE ${SANITIZER_OPTIONS})
    target_link_options (${target_name} PRIVATE ${SANITIZER_OPTIONS})
  endif ()
endmacro ()

function (configure_test test_name)
  message ("-- Configuring test: ${test_name}")
  add_test_macro (${test_name} ${test_name} FALSE)
  message ("-- Configuring test: ${test_name}_sanitizer")
  add_test_macro ("${test_name}_sanitizer" ${test_name} TRUE)
endfunction ()

if (RUN_TEST)
  configure_test (nfail_malloc_test)
  configure_test (sxg_buffer_test)
  configure_test (sxg_cbor_test)
  configure_test (sxg_cert_chain_test)
  configure_test (sxg_codec_test)
  configure_test (sxg_encoded_response_test)
  configure_test (sxg_generate_test)
  configure_test (sxg_header_test)
  configure_test (sxg_sig_test)
  configure_test (sxg_signer_list_test)
  configure_test (toplevel_test)
endif ()

# ##############################################################################
# Fuzzing
# ##############################################################################

set (fuzzer_option "-fsanitize=address,fuzzer")
function (configure_fuzzer fuzzer_name)
  message ("-- Configuring fuzzer: ${fuzzer_name}")
  add_executable (${fuzzer_name} fuzzers/${fuzzer_name}.cc)
  target_compile_options (${fuzzer_name} PRIVATE ${fuzzer_option})
  target_link_options (${fuzzer_name} PRIVATE ${fuzzer_option})

  add_dependencies (${fuzzer_name} sxg)
  target_link_libraries (${fuzzer_name} PRIVATE sxg ${OPENSSL_LIBRARIES})
  target_include_directories (${fuzzer_name}
                              PRIVATE ${PROJECT_SOURCE_DIR}/include)
endfunction ()

# check_cxx_compiler_flag command may be good.
try_compile (
  fuzzer_available ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/fuzzers/signer_fuzzer.cc
  CMAKE_FLAGS "-DINCLUDE_DIRECTORIES:STRING=${PROJECT_SOURCE_DIR}/include"
  LINK_LIBRARIES "sxg ${OPENSSL_LIBRARIES}" LINK_OPTIONS ${fuzzer_option})

if (RUN_TEST)
  if (fuzzer_available)
    configure_fuzzer (signer_fuzzer)
  else ()
    message (
      "fuzzer disabled because the compiler ${CMAKE_CXX_COMPILER} does not support [${fuzzer_option}] option"
    )
  endif ()
endif ()
