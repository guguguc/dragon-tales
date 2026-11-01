target_sources(libdragon
        PRIVATE
        IGNIL.cpp
        IGNILSimplify.cpp
)

# Z3-backed symbolic execution and effect tracking remain optional.
if(DRAGON_USE_Z3)
    target_sources(libdragon
            PRIVATE
            SymbolicExecutor.cpp
            StateSummary.cpp
            SymbolicProjection.cpp
            MemoryEffects.cpp
    )
endif()
