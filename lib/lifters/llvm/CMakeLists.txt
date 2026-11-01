target_sources(libdragon
        PRIVATE
        LLVMLifter.cpp
        LLVMOptimization.cpp
)

if(DRAGON_USE_Z3)
    target_sources(libdragon PRIVATE LLVMExpression.cpp)
endif()

add_subdirectory(passes)
