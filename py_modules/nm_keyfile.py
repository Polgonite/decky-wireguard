"""In-memory keyfile conversion using the same system libnm as nmcli."""

import ctypes as C
from contextlib import ExitStack


class KeyfileCodec:
    def __init__(self):
        self.lib = C.CDLL("libnm.so.0")
        p, s, u, size = C.c_void_p, C.c_char_p, C.c_uint, C.c_size_t
        for name, result, args in (
            ("g_dbus_message_new_from_blob", p, [s, size, u, p]),
            ("g_dbus_message_get_body", p, [p]),
            ("g_variant_get_child_value", p, [p, size]),
            ("nm_simple_connection_new", p, []),
            ("nm_connection_replace_settings", C.c_int, [p, p, p]),
            ("nm_keyfile_write", p, [p, u, p, p, p]),
            ("g_key_file_to_data", p, [p, C.POINTER(size), p]),
            ("g_key_file_new", p, []),
            ("g_key_file_load_from_data", C.c_int, [p, s, size, u, p]),
            ("nm_keyfile_read", p, [p, s, u, p, p, p]),
            ("nm_connection_to_dbus", p, [p, u]),
            ("g_variant_take_ref", p, [p]),
            ("g_variant_new_tuple", p, [C.POINTER(p), size]),
            ("g_dbus_message_set_body", None, [p, p]),
            ("g_dbus_message_to_blob", p, [p, C.POINTER(size), u, p]),
            ("g_variant_unref", None, [p]),
            ("g_object_unref", None, [p]),
            ("g_key_file_unref", None, [p]),
            ("g_free", None, [p]),
        ):
            func = getattr(self.lib, name)
            func.argtypes, func.restype = args, result

    @staticmethod
    def _own(stack, ptr, release):
        if not ptr:
            raise ValueError("NetworkManager could not convert the offline profile.")
        stack.callback(release, ptr)
        return ptr

    def _message(self, stack, blob):
        lib = self.lib
        return self._own(stack, lib.g_dbus_message_new_from_blob(blob, len(blob), 0, None),
                         lib.g_object_unref)

    def to_keyfile(self, blob: bytes) -> bytes:
        lib = self.lib
        with ExitStack() as stack:
            msg = self._message(stack, blob)
            settings = self._own(stack, lib.g_variant_get_child_value(
                lib.g_dbus_message_get_body(msg), 0), lib.g_variant_unref)
            # Do not normalize an intermediate draft: pending offline edits may
            # still remove a gateway or routes belonging to a newly disabled family.
            profile = self._own(stack, lib.nm_simple_connection_new(), lib.g_object_unref)
            if not lib.nm_connection_replace_settings(profile, settings, None):
                raise ValueError("NetworkManager could not parse the offline profile.")
            keyfile = self._own(stack, lib.nm_keyfile_write(profile, 0, None, None, None),
                                lib.g_key_file_unref)
            size = C.c_size_t()
            data = self._own(stack, lib.g_key_file_to_data(keyfile, C.byref(size), None), lib.g_free)
            return C.string_at(data, size.value)

    def from_keyfile(self, blob: bytes, text: bytes) -> bytes:
        lib = self.lib
        with ExitStack() as stack:
            keyfile = self._own(stack, lib.g_key_file_new(), lib.g_key_file_unref)
            if not lib.g_key_file_load_from_data(keyfile, text, len(text), 0, None):
                raise ValueError("NetworkManager returned an unreadable offline profile.")
            profile = self._own(stack, lib.nm_keyfile_read(keyfile, b"/", 0, None, None, None),
                                lib.g_object_unref)
            settings = self._own(stack, lib.nm_connection_to_dbus(profile, 0), lib.g_variant_unref)
            lib.g_variant_take_ref(settings)
            msg = self._message(stack, blob)
            body = lib.g_variant_new_tuple((C.c_void_p * 1)(settings), 1)
            lib.g_dbus_message_set_body(msg, body)  # sinks the floating tuple
            size = C.c_size_t()
            data = self._own(stack, lib.g_dbus_message_to_blob(msg, C.byref(size), 0, None),
                             lib.g_free)
            return C.string_at(data, size.value)
