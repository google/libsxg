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
set (CMAKE_PROJECT_VERSION_MINOR "1")
set (CMAKE_PROJECT_VERSION_PATCH "0")

option (RUN_TEST
  "If false, build libsxg without building tests.\
  Building tests of libsxg requires more recent version of cmake (>= 3.13).\
  Tests include fuzzer will be disabled automatically if it is not supported
  by the compiler."
  TRUE
)

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
set_property(
  DIRECTORY ${PROJECT_SOURCE_DIR}
  PROPERTY EP_UPDATE_DISCONNECTED 1
)

find_package (OpenSSL REQUIRED)

add_library(sxg
  src/sxg_buffer.c
  src/sxg_buffer_debug.c
  src/sxg_cert_chain.c
  src/sxg_codec.c
  src/sxg_generate.c
  src/sxg_raw_response.c
  src/sxg_encoded_response.c
  src/sxg_header.c
  src/sxg_sig.c
  src/sxg_signer_list.c
)

target_include_directories(
  sxg
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(
  sxg
  PRIVATE
    ${OPENSSL_LIBRARIES}
)

add_executable(
  gensxg
    src/gensxg.c
)

target_include_directories(
  gensxg
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(
  gensxg
  PRIVATE
    ${OPENSSL_LIBRARIES}
    sxg
    )
  
add_executable(
  gencertchain
    src/gencertchain.c
)

target_include_directories(
  gencertchain
  PRIVATE
    ${PROJECT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(
  gencertchain
  PRIVATE
    ${OPENSSL_LIBRARIES}
    sxg
)

########################################
## Installing
########################################

set_target_properties (sxg PROPERTIES PUBLIC_HEADER "${HEADERS}")
install (
  TARGETS sxg
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  COMPONENT library
)
install (
  DIRECTORY ${CMAKE_SOURCE_DIR}/include/
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include
  FILES_MATCHING PATTERN "*.h*"
)
install (
  TARGETS gensxg
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

########################################
## Testing
########################################
if (RUN_TEST)
  enable_testing ()

  file (COPY tests/testdata DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

  ExternalProject_Add(
    gtest
    GIT_REPOSITORY https://github.com/google/googletest
    GIT_TAG master
    SOURCE_DIR ${PROJECT_BINARY_DIR}/third_party/gtest
    BINARY_DIR ${PROJECT_BINARY_DIR}/gtest
    INSTALL_COMMAND ""
  )
  add_library (libgtest IMPORTED STATIC GLOBAL)
  add_dependencies (libgtest gtest)
  set_target_properties(
    libgtest PROPERTIES
      "IMPORTED_LOCATION" "${PROJECT_BINARY_DIR}/gtest/lib/libgtest.a"
      "IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}"
  )
  add_library (libgtest_main IMPORTED STATIC GLOBAL)
  add_dependencies (libgtest_main gtest)
  set_target_properties(
    libgtest_main PROPERTIES
      "IMPORTED_LOCATION" "${PROJECT_BINARY_DIR}/gtest/lib/libgtest_main.a"
      "IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}"
  )
  set (GTEST_INCLUDE ${PROJECT_BINARY_DIR}/third_party/gtest/googletest/include)

  add_library(test_util
    SHARED
    tests/test_util.cc)
  target_include_directories(
    test_util
    PRIVATE
      ${PROJECT_SOURCE_DIR}/include
      ${GTEST_INCLUDE}
  )
  add_dependencies (test_util sxg libgtest libgtest_main gtest)
  target_link_libraries (
    test_util
    INTERFACE
      libgtest
      libgtest_main
      pthread
      sxg
      ${OPENSSL_LIBRARIES}
  )
endif ()

macro (add_test_macro target_name test_name)
  add_executable (${target_name} tests/${test_name}.cc)
  add_test(
    NAME ${target_name}
    COMMAND ${target_name}
  )
  add_dependencies (${target_name} libgtest libgtest_main gtest sxg test_util)
  target_link_libraries (
    ${target_name}
    PRIVATE
      libgtest
      libgtest_main
      pthread
      sxg
      test_util
      ${OPENSSL_LIBRARIES})
  target_include_directories(
    ${target_name}
    PRIVATE
      ${PROJECT_SOURCE_DIR}/include
      ${GTEST_INCLUDE}
  )
endmacro ()

function (add_plain_test test_name)
  add_test_macro (${test_name} ${test_name})
endfunction ()

set (SANITIZER_OPTIONS "-fsanitize=address,leak,undefined")
function (add_sanitizer_test test_name)
  add_test_macro ("${test_name}_sanitizer" ${test_name})
endfunction ()

function (configure_test test_name)
  message ("-- Configuring test: ${test_name}")
  add_plain_test (${test_name})
  add_sanitizer_test (${test_name})
endfunction ()

if (RUN_TEST)
  configure_test (nfail_malloc_test)
  configure_test (sxg_buffer_test)
  configure_test (sxg_cert_chain_test)
  configure_test (sxg_codec_test)
  configure_test (sxg_encoded_response_test)
  configure_test (sxg_generate_test)
  configure_test (sxg_header_test)
  configure_test (sxg_sig_test)
  configure_test (sxg_signer_list_test)
  configure_test (toplevel_test)
endif ()


########################################
## Fuzzing
########################################

set (fuzzer_option "-fsanitize=address,fuzzer")
function (configure_fuzzer fuzzer_name)
  message ("-- Configuring fuzzer: ${fuzzer_name}")
  add_executable (${fuzzer_name} fuzzers/${fuzzer_name}.cc)
  target_compile_options(
    ${fuzzer_name}
    PRIVATE
      ${fuzzer_option}
  )
  target_link_options(
    ${fuzzer_name}
    PRIVATE
      ${fuzzer_option}
  )

  add_dependencies (${fuzzer_name} sxg)
  target_link_libraries(
    ${fuzzer_name}
    PRIVATE
      sxg
      ${OPENSSL_LIBRARIES}
  )
  target_include_directories(
    ${fuzzer_name}
    PRIVATE
      ${PROJECT_SOURCE_DIR}/include
  )
endfunction ()

# check_cxx_compiler_flag command may be good.
try_compile(fuzzer_available
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/fuzzers/signer_fuzzer.cc
  CMAKE_FLAGS "-DINCLUDE_DIRECTORIES:STRING=${PROJECT_SOURCE_DIR}/include"
  LINK_LIBRARIES "sxg ${OPENSSL_LIBRARIES}"
  LINK_OPTIONS ${fuzzer_option}
)

if (RUN_TEST)
  if (fuzzer_available)
    configure_fuzzer(signer_fuzzer)
  else ()
    message ("fuzzer disabled because the compiler ${CMAKE_CXX_COMPILER} does not support [${fuzzer_option}] option")
  endif ()
endif ()
