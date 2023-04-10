cmake_minimum_required(VERSION 3.10)
project(libco)

# This for mac osx only
set(CMAKE_MACOSX_RPATH 0)

# Set lib version
set(LIBCO_VERSION   0.5)

# Set cflags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -fno-strict-aliasing -O2 -Wall -export-dynamic -Wall -pipe  -D_GNU_SOURCE -D_REENTRANT -fPIC -Wno-deprecated -m64")

# Use c and asm
enable_language(C ASM ASM-ATT )
set_source_files_properties(
    ${SRCS}
    PROPERTIES
    LANGUAGE CXX
  )

# Add source files
# list(APPEND CMAKE_C_SOURCE_FILE_EXTENSIONS .S)
aux_source_directory(co SOURCE_FILES)
list(APPEND SOURCE_FILES co/coctx_swap.S)
file(GLOB HEADER_FILES co/*.h)


# Add static and shared library target
add_library(co_static STATIC ${SOURCE_FILES})
add_library(co_shared SHARED ${SOURCE_FILES})

# Set library output name
set_target_properties(co_static PROPERTIES OUTPUT_NAME co)
set_target_properties(co_shared PROPERTIES OUTPUT_NAME co)

set_target_properties(co_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
set_target_properties(co_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)

# Set shared library version, will generate libcolib.${LIBCO_VERSION}.so and a symbol link named libcolib.so
# For mac osx, the extension name will be .dylib
set_target_properties(co_shared PROPERTIES VERSION ${LIBCO_VERSION} SOVERSION ${LIBCO_VERSION})
install(TARGETS co_static co_shared)

install(FILES ${HEADER_FILES}
    DESTINATION include/co
)
include_directories(co)
aux_source_directory(examples EXAMPLE_FILES)

foreach(SRC ${EXAMPLE_FILES})
    string(REGEX REPLACE ".*/" "" TMP ${SRC})
    string(REGEX REPLACE ".cpp$" "" TMP ${TMP})
    string(REGEX REPLACE ".c$" "" TMP ${TMP})
    add_executable(${TMP} ${SRC})
    target_link_libraries(${TMP} co_static pthread dl)
endforeach(SRC ${EXAMPLE_FILES})

