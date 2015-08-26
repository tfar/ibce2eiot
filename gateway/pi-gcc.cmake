INCLUDE(CMakeForceCompiler)

SET(CMAKE_SYSTEM_NAME Linux)
#set(CMAKE_SYSROOT /Volumes/tank/pi_gateway)

CMAKE_FORCE_C_COMPILER(arm-linux-gnueabihf-gcc GNU)
CMAKE_FORCE_CXX_COMPILER(arm-linux-gnueabihf-g++ GNU)


set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

include_directories( SYSTEM /Volumes/tank/pi_gateway/usr/include/arm-linux-gnueabihf)