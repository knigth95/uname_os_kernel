OUTPUT_ARCH(riscv)
ENTRY(_entry)
BASE_ADDRESS = 0x80200000;

SECTIONS
{
    . = BASE_ADDRESS;
    s_kernel = .;

    s_text = .;
    .text : {
        *(.text.entry)
        . = ALIGN(0x1000);
        s_tramponline = .;
        *(.text.tramponline)
        . = ALIGN(0x1000);
        e_tramponline = .;
        *(.text .text.*)
    }

    . = ALIGN(4K);
    e_text = .;

    s_rodata = .;
    .rodata : {
        *(.rodata .rodata.*)
    }
    . = ALIGN(4K);
    e_rodata = .;

    s_data = .;
    .data : {
        *(.data)
        *(.data.*)
        *(.sdata .sdata.*)
    }
    . = ALIGN(4K);
    e_data = .;

    .bss : {
        *(.bss.stack)
        s_bss = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
    }

    . = ALIGN(4K);
    e_bss = .;
    e_kernel = .;

    e_mem = 0x88000000;

    /DISCARD/ : {
        *(.eh_frame)
    }
}
