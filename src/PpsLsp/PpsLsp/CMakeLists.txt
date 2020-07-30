# CMakeList.txt : CMake project for PpsLsp, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)


IF(MSVC)
SET(MSVC_LIBS ws2_32)
ELSE(MSVC)
SET(MSVC_LIBS )
ENDIF(MSVC)
# Add source to this project's executable.
add_executable (PpsLsp "PpsLsp.cpp" "PpsLsp.h")
target_link_libraries(PpsLsp
PRIVATE ${MSVC_LIBS}
)
add_executable (PpsLspTool "PpsLspTool.cpp")
target_link_libraries(PpsLspTool
PRIVATE ${MSVC_LIBS}
)

add_library (ppslspdll SHARED "PpsLspDll.cpp")
target_link_libraries(ppslspdll
PRIVATE ${MSVC_LIBS}
)

# TODO: Add tests and install targets if needed.
