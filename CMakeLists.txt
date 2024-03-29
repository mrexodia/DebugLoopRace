# This file is automatically generated from cmake.toml - DO NOT EDIT
# See https://github.com/build-cpp/cmkr for more information

cmake_minimum_required(VERSION 3.15)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
	message(FATAL_ERROR "In-tree builds are not supported. Run CMake from a separate directory: cmake -B build")
endif()

# Regenerate CMakeLists.txt automatically in the root project
set(CMKR_ROOT_PROJECT OFF)
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
	set(CMKR_ROOT_PROJECT ON)

	# Bootstrap cmkr
	include(cmkr.cmake OPTIONAL RESULT_VARIABLE CMKR_INCLUDE_RESULT)
	if(CMKR_INCLUDE_RESULT)
		cmkr()
	endif()

	# Enable folder support
	set_property(GLOBAL PROPERTY USE_FOLDERS ON)
endif()

# Create a configure-time dependency on cmake.toml to improve IDE support
if(CMKR_ROOT_PROJECT)
	configure_file(cmake.toml cmake.toml COPYONLY)
endif()

project(DebugLoopRace
	VERSION
		0.1.0
)

# Target DebugLoop
set(CMKR_TARGET DebugLoop)
set(DebugLoop_SOURCES "")

list(APPEND DebugLoop_SOURCES
	"src/DebugLoop/DebugLoop.cpp"
)

list(APPEND DebugLoop_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${DebugLoop_SOURCES})
add_executable(DebugLoop)

if(DebugLoop_SOURCES)
	target_sources(DebugLoop PRIVATE ${DebugLoop_SOURCES})
endif()

get_directory_property(CMKR_VS_STARTUP_PROJECT DIRECTORY ${PROJECT_SOURCE_DIR} DEFINITION VS_STARTUP_PROJECT)
if(NOT CMKR_VS_STARTUP_PROJECT)
	set_property(DIRECTORY ${PROJECT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT DebugLoop)
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${DebugLoop_SOURCES})

target_include_directories(DebugLoop PRIVATE
	include
)

target_link_options(DebugLoop PRIVATE
	"/INCREMENTAL:NO"
)

set_target_properties(DebugLoop PROPERTIES
	VS_DEBUGGER_COMMAND_ARGUMENTS
		"\"$<TARGET_FILE:DebugMe>\""
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target DebugMe
set(CMKR_TARGET DebugMe)
set(DebugMe_SOURCES "")

list(APPEND DebugMe_SOURCES
	"src/DebugMe/DebugMe.cpp"
)

list(APPEND DebugMe_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${DebugMe_SOURCES})
add_executable(DebugMe)

if(DebugMe_SOURCES)
	target_sources(DebugMe PRIVATE ${DebugMe_SOURCES})
endif()

get_directory_property(CMKR_VS_STARTUP_PROJECT DIRECTORY ${PROJECT_SOURCE_DIR} DEFINITION VS_STARTUP_PROJECT)
if(NOT CMKR_VS_STARTUP_PROJECT)
	set_property(DIRECTORY ${PROJECT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT DebugMe)
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${DebugMe_SOURCES})

target_link_options(DebugMe PRIVATE
	"/DYNAMICBASE:NO"
	"/INCREMENTAL:NO"
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target MemoryTest
set(CMKR_TARGET MemoryTest)
set(MemoryTest_SOURCES "")

list(APPEND MemoryTest_SOURCES
	"src/MemoryTest/MemoryTest.cpp"
)

list(APPEND MemoryTest_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${MemoryTest_SOURCES})
add_executable(MemoryTest)

if(MemoryTest_SOURCES)
	target_sources(MemoryTest PRIVATE ${MemoryTest_SOURCES})
endif()

get_directory_property(CMKR_VS_STARTUP_PROJECT DIRECTORY ${PROJECT_SOURCE_DIR} DEFINITION VS_STARTUP_PROJECT)
if(NOT CMKR_VS_STARTUP_PROJECT)
	set_property(DIRECTORY ${PROJECT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT MemoryTest)
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${MemoryTest_SOURCES})

target_link_options(MemoryTest PRIVATE
	"/DYNAMICBASE:NO"
	"/INCREMENTAL:NO"
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target AntiDebugHandle
set(CMKR_TARGET AntiDebugHandle)
set(AntiDebugHandle_SOURCES "")

list(APPEND AntiDebugHandle_SOURCES
	"src/AntiDebugHandle/AntiDebugHandle.cpp"
)

list(APPEND AntiDebugHandle_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${AntiDebugHandle_SOURCES})
add_executable(AntiDebugHandle)

if(AntiDebugHandle_SOURCES)
	target_sources(AntiDebugHandle PRIVATE ${AntiDebugHandle_SOURCES})
endif()

get_directory_property(CMKR_VS_STARTUP_PROJECT DIRECTORY ${PROJECT_SOURCE_DIR} DEFINITION VS_STARTUP_PROJECT)
if(NOT CMKR_VS_STARTUP_PROJECT)
	set_property(DIRECTORY ${PROJECT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT AntiDebugHandle)
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${AntiDebugHandle_SOURCES})

target_link_options(AntiDebugHandle PRIVATE
	"/DYNAMICBASE:NO"
	"/INCREMENTAL:NO"
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

# Target TestTitanEngine
set(CMKR_TARGET TestTitanEngine)
set(TestTitanEngine_SOURCES "")

list(APPEND TestTitanEngine_SOURCES
	"src/TestTitanEngine/TestTitanEngine.cpp"
	"src/TestTitanEngine/TitanEngine.h"
)

list(APPEND TestTitanEngine_SOURCES
	cmake.toml
)

set(CMKR_SOURCES ${TestTitanEngine_SOURCES})
add_executable(TestTitanEngine)

if(TestTitanEngine_SOURCES)
	target_sources(TestTitanEngine PRIVATE ${TestTitanEngine_SOURCES})
endif()

get_directory_property(CMKR_VS_STARTUP_PROJECT DIRECTORY ${PROJECT_SOURCE_DIR} DEFINITION VS_STARTUP_PROJECT)
if(NOT CMKR_VS_STARTUP_PROJECT)
	set_property(DIRECTORY ${PROJECT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT TestTitanEngine)
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${TestTitanEngine_SOURCES})

target_link_directories(TestTitanEngine PRIVATE
	"src/TestTitanEngine"
)

if(CMAKE_SIZEOF_VOID_P EQUAL 8) # x64
	target_link_libraries(TestTitanEngine PRIVATE
		TitanEngine_x64
	)
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 4) # x32
	target_link_libraries(TestTitanEngine PRIVATE
		TitanEngine_x86
	)
endif()

set_target_properties(TestTitanEngine PROPERTIES
	VS_DEBUGGER_COMMAND_ARGUMENTS
		"\"$<TARGET_FILE:DebugMe>\""
)

unset(CMKR_TARGET)
unset(CMKR_SOURCES)

