function(bpf prefix)
    add_custom_target(${prefix}_bpf ALL
            COMMAND clang --target=bpf -nostdinc -S -I/usr/include/linux -I${CMAKE_SOURCE_DIR}/include -I${LINUX_SOURCE}/arch/x86/include -I/usr/include -I${LINUX_SOURCE}/arch/x86/include/uapi -I${LINUX_SOURCE}/arch/x86/include/generated -I${LINUX_SOURCE}/arch/x86/include/generated/uapi -I${LINUX_SOURCE}/include -I${LINUX_SOURCE}/include/uapi -I${LINUX_SOURCE}/include/generated/uapi -I${LINUX_SOURCE}/tools/testing/selftests/bpf -include ${LINUX_SOURCE}/include/linux/kconfig.h -D__KERNEL__ -D__ASM_SYSREG_H -D__BPF_TRACING__ -D__TARGET_ARCH_x86 -Wno-implicit-function-declaration -O3 -emit-llvm -g -c ${CMAKE_SOURCE_DIR}/src/${prefix}.c -o ${CMAKE_BINARY_DIR}/${prefix}.ll
            COMMAND llc -march=bpf -filetype=obj -o ${CMAKE_BINARY_DIR}/${prefix}.o ${CMAKE_BINARY_DIR}/${prefix}.ll
    )
    add_dependencies(rocksdb ${prefix}_bpf)
endfunction()
bpf(check_done.c)
bpf(update_ring.c)
