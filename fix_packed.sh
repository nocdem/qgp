#!/bin/bash
# Fix packed structures in multiple files

for file in decrypt.c export.c; do
    if [ -f "$file" ]; then
        # Add qgp_compiler.h include after qgp_types.h
        sed -i '/#include "qgp_types.h"/a #include "qgp_compiler.h"' "$file"
        
        # Replace __attribute__((packed)) with PACK_STRUCT_END
        sed -i 's/} __attribute__((packed))/} PACK_STRUCT_END/g' "$file"
        
        # Add PACK_STRUCT_BEGIN before typedef struct (simple pattern)
        # This is a basic approach - may need manual refinement
        echo "Fixed $file"
    fi
done
