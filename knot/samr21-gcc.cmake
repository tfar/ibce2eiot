INCLUDE(CMakeForceCompiler)

SET(CMAKE_SYSTEM_NAME Generic)

CMAKE_FORCE_C_COMPILER(arm-none-eabi-gcc GNU)
CMAKE_FORCE_CXX_COMPILER(arm-none-eabi-g++ GNU)
