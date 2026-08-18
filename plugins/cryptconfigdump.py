from volatility3.framework import interfaces, renderers, exceptions
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints


class CryptConfigDumpFast(interfaces.plugins.PluginInterface):
    """Dump an exact kernel virtual-address range without pointer scanning."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.IntRequirement(
                name="address",
                description="Kernel virtual address to dump",
            ),
            requirements.IntRequirement(
                name="length",
                description="Number of bytes to dump",
                optional=True,
                default=0x800,
            ),
        ]

    @staticmethod
    def _hex_preview(data, limit=64):
        preview = data[:limit]
        return " ".join(f"{byte:02x}" for byte in preview)

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[kernel.layer_name]

        address = int(self.config["address"])
        length = int(self.config["length"])

        if address <= 0:
            raise ValueError("Address must be greater than zero")

        if length <= 0:
            raise ValueError("Length must be greater than zero")

        # Tránh vô tình dump vùng quá lớn do nhập sai tham số.
        if length > 0x100000:
            raise ValueError(
                f"Refusing to dump 0x{length:x} bytes; "
                "maximum allowed length is 0x100000"
            )

        filename = f"crypt_config_0x{address:x}_0x{length:x}.bin"

        try:
            # Chỉ thực hiện đúng một lần đọc virtual memory.
            data = layer.read(address, length, pad=False)

        except exceptions.InvalidAddressException as error:
            raise ValueError(
                f"Cannot read kernel virtual address 0x{address:x}: {error}"
            ) from error

        if not data:
            raise ValueError(
                f"No data returned from address 0x{address:x}"
            )

        with self.open(filename) as output_file:
            output_file.write(data)

        yield (
            0,
            (
                format_hints.Hex(address),
                len(data),
                filename,
                self._hex_preview(data),
            ),
        )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Address", format_hints.Hex),
                ("BytesDumped", int),
                ("OutputFile", str),
                ("First64Bytes", str),
            ],
            self._generator(),
        )
