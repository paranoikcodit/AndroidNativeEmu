from unicorn import *
from unicorn.arm_const import *

STACK_OFFSET = 8


from typing import List, Tuple


def _to_le16(value: int) -> List[int]:
    return [value & 0xFF, (value >> 8) & 0xFF]


def _encode_movw(rd: int, imm16: int) -> List[int]:
    i = (imm16 >> 11) & 0x1
    imm4 = (imm16 >> 12) & 0xF
    imm3 = (imm16 >> 8) & 0x7
    imm8 = imm16 & 0xFF
    half1 = 0xF240 | (i << 10) | imm4
    half2 = (imm3 << 12) | (rd << 8) | imm8
    return _to_le16(half1) + _to_le16(half2)


def _encode_movt(rd: int, imm16: int) -> List[int]:
    i = (imm16 >> 11) & 0x1
    imm4 = (imm16 >> 12) & 0xF
    imm3 = (imm16 >> 8) & 0x7
    imm8 = imm16 & 0xFF
    half1 = 0xF2C0 | (i << 10) | imm4
    half2 = (imm3 << 12) | (rd << 8) | imm8
    return _to_le16(half1) + _to_le16(half2)


def assemble_hook_stub(hook_id: int) -> Tuple[List[int], int]:
    code: List[int] = []
    code += _to_le16(0xB510)

    if hook_id <= 0xFF:
        code += _to_le16(0x2400 | hook_id)
    else:
        code += _encode_movw(4, hook_id & 0xFFFF)
        upper = (hook_id >> 16) & 0xFFFF
        if upper:
            code += _encode_movt(4, upper)

    code += _to_le16(0x4624)
    code += _to_le16(0xBD10)

    instr_count = len(code) // 2
    return code, instr_count


# Utility class to create a bridge between ARM and Python.
class Hooker:
    """
    :type emu androidemu.emulator.Emulator
    """

    def __init__(self, emu, base_addr, size):
        self._emu = emu
        self._size = size
        self._current_id = 0xFF00
        self._hooks = dict()
        self._hook_magic = base_addr
        self._hook_start = base_addr + 4
        self._hook_current = self._hook_start
        self._emu.uc.hook_add(
            UC_HOOK_CODE, self._hook, None, self._hook_start, self._hook_start + size
        )

    def _get_next_id(self):
        idx = self._current_id
        self._current_id += 1
        return idx

    def write_function(self, func):
        # Get the hook id.
        hook_id = self._get_next_id()
        hook_addr = self._hook_current

        asm_bytes_list, asm_count = assemble_hook_stub(hook_id)

        if asm_count != 4:
            raise ValueError("Expected asm_count to be 4 instead of %u." % asm_count)

        # Write assembly code to the emulator.
        self._emu.uc.mem_write(hook_addr, bytes(asm_bytes_list))

        # Save results.
        self._hook_current += len(asm_bytes_list)
        self._hooks[hook_id] = func

        return hook_addr

    def write_function_table(self, table):
        if not isinstance(table, dict):
            raise ValueError("Expected a dictionary for the function table.")

        index_max = int(max(table, key=int)) + 1

        # First, we write every function and store its result address.
        hook_map = dict()

        for index, func in table.items():
            hook_map[index] = self.write_function(func)

        # Then we write the function table.
        table_bytes = b""
        table_address = self._hook_current

        for index in range(0, index_max):
            address = hook_map[index] if index in hook_map else 0
            table_bytes += int(address + 1).to_bytes(
                4, byteorder="little"
            )  # + 1 because THUMB.

        self._emu.uc.mem_write(table_address, table_bytes)
        self._hook_current += len(table_bytes)

        # Then we write the a pointer to the table.
        ptr_address = self._hook_current
        self._emu.uc.mem_write(
            ptr_address, table_address.to_bytes(4, byteorder="little")
        )
        self._hook_current += 4

        return ptr_address, table_address

    def _hook(self, uc, address, size, user_data):
        # Check if instruction is "MOV R4, R4"
        if size != 2 or self._emu.uc.mem_read(address, size) != b"\x24\x46":
            return

        # Find hook.
        hook_id = self._emu.uc.reg_read(UC_ARM_REG_R4)
        hook_func = self._hooks[hook_id]

        # Call hook.
        try:
            hook_func(self._emu)
        except:
            # Make sure we catch exceptions inside hooks and stop emulation.
            uc.emu_stop()
            raise
