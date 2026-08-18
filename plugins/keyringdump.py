import struct

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints


class KeyringDump(interfaces.plugins.PluginInterface):
    """Locate a Linux key by type/description and dump its payload."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.StringRequirement(
                name="description",
                description="Exact key description",
            ),
            requirements.StringRequirement(
                name="key_type",
                description="Expected key type",
                optional=True,
                default="logon",
            ),
            requirements.IntRequirement(
                name="expected_size",
                description="Expected payload size",
                optional=True,
                default=64,
            ),
        ]

    @staticmethod
    def _read_cstring(layer, address, maximum=512):
        if not address:
            return ""

        try:
            raw = layer.read(address, maximum, pad=False)
        except Exception:
            return ""

        return raw.split(b"\x00", 1)[0].decode(
            "utf-8",
            errors="replace",
        )

    @staticmethod
    def _payload_offsets(kernel):
        # user_key_payload normally has:
        #   rcu_head   @ 0x00, size 0x10
        #   datalen    @ 0x10
        #   data[]     @ 0x18
        datalen_offset = 0x10
        data_offset = 0x18

        try:
            payload_type = kernel.get_type("user_key_payload")
            datalen_offset = payload_type.relative_child_offset("datalen")
            data_offset = payload_type.relative_child_offset("data")
        except Exception:
            pass

        return datalen_offset, data_offset

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[kernel.layer_name]

        wanted_description = str(self.config["description"])
        wanted_type = str(self.config["key_type"])
        expected_size = int(self.config["expected_size"])

        # Accept the complete dm-crypt string too.
        prefix = wanted_type + ":"
        if wanted_description.startswith(prefix):
            wanted_description = wanted_description[len(prefix):]

        root = kernel.object_from_symbol("key_serial_tree")
        root_node = int(root.rb_node)

        serial_node_offset = kernel.get_type(
            "key"
        ).relative_child_offset("serial_node")

        datalen_offset, data_offset = self._payload_offsets(kernel)

        stack = []
        visited = set()
        matches = 0

        if root_node:
            stack.append(root_node)

        while stack:
            node_address = stack.pop()

            if not node_address or node_address in visited:
                continue

            visited.add(node_address)

            if len(visited) > 100000:
                raise ValueError("RB-tree traversal limit exceeded")

            try:
                node = kernel.object(
                    object_type="rb_node",
                    offset=node_address,
                    absolute=True,
                )

                left = int(node.rb_left)
                right = int(node.rb_right)

                if left:
                    stack.append(left)
                if right:
                    stack.append(right)

                key_address = node_address - serial_node_offset
                key_object = kernel.object(
                    object_type="key",
                    offset=key_address,
                    absolute=True,
                )

                serial = int(key_object.serial)

                description_pointer = int(key_object.description)
                description = self._read_cstring(
                    layer,
                    description_pointer,
                )

                key_type_pointer = int(key_object.type)
                key_type_object = kernel.object(
                    object_type="key_type",
                    offset=key_type_pointer,
                    absolute=True,
                )

                type_name_pointer = int(key_type_object.name)
                type_name = self._read_cstring(
                    layer,
                    type_name_pointer,
                    maximum=64,
                )

            except Exception:
                continue

            if type_name != wanted_type:
                continue

            if description != wanted_description:
                continue

            matches += 1

            try:
                payload_pointer = int(key_object.payload.data[0])
            except Exception:
                payload_pointer = 0

            datalen = 0
            output_name = ""

            if payload_pointer:
                try:
                    header_size = max(data_offset, datalen_offset + 2)
                    header = layer.read(
                        payload_pointer,
                        header_size,
                        pad=False,
                    )

                    datalen = struct.unpack_from(
                        "<H",
                        header,
                        datalen_offset,
                    )[0]

                    if not 0 < datalen <= 32767:
                        raise ValueError(
                            f"Invalid payload length {datalen}"
                        )

                    payload = layer.read(
                        payload_pointer + data_offset,
                        datalen,
                        pad=False,
                    )

                    output_name = (
                        f"logon_key_{serial}_"
                        f"{datalen}_bytes.bin"
                    )

                    with self.open(output_name) as output_file:
                        output_file.write(payload)

                except Exception as error:
                    output_name = f"ERROR: {error}"

            status = (
                "SIZE_OK"
                if datalen == expected_size
                else f"EXPECTED_{expected_size}"
            )

            yield (
                0,
                (
                    format_hints.Hex(key_address),
                    serial,
                    type_name,
                    description,
                    format_hints.Hex(payload_pointer),
                    datalen,
                    status,
                    output_name,
                ),
            )

        if matches == 0:
            yield (
                0,
                (
                    format_hints.Hex(0),
                    0,
                    wanted_type,
                    wanted_description,
                    format_hints.Hex(0),
                    0,
                    "NOT_FOUND",
                    "",
                ),
            )

    def run(self):
        return renderers.TreeGrid(
            [
                ("KeyAddress", format_hints.Hex),
                ("Serial", int),
                ("Type", str),
                ("Description", str),
                ("PayloadAddress", format_hints.Hex),
                ("Datalen", int),
                ("Status", str),
                ("OutputFile", str),
            ],
            self._generator(),
        )
