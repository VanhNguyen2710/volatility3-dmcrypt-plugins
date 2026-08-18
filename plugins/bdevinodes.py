from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints


class BdevInodes(interfaces.plugins.PluginInterface):
    """Lists block-device inodes from blockdev_superblock."""

    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    @staticmethod
    def ptr_value(obj):
        try:
            return int(obj)
        except Exception:
            return int(obj.vol.offset)

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        sb_symbol = kernel.object_from_symbol("blockdev_superblock")

        try:
            sb = sb_symbol.dereference()
        except Exception:
            sb = sb_symbol

        head = sb.s_inodes
        head_addr = int(head.vol.offset)

        inode_type = kernel.get_type("inode")
        link_offset = inode_type.relative_child_offset("i_sb_list")

        current = self.ptr_value(head.next)
        seen = set()

        for _ in range(65536):
            if not current or current == head_addr or current in seen:
                break

            seen.add(current)

            inode_addr = current - link_offset

            try:
                inode = kernel.object(
                    object_type="inode",
                    offset=inode_addr,
                    absolute=True,
                )

                raw_dev = int(inode.i_rdev)
                major = raw_dev >> 20
                minor = raw_dev & ((1 << 20) - 1)

                mapping_ptr = inode.i_mapping
                mapping_addr = self.ptr_value(mapping_ptr)

                try:
                    mapping = mapping_ptr.dereference()
                except Exception:
                    mapping = mapping_ptr

                try:
                    nrpages = int(mapping.nrpages)
                except Exception:
                    nrpages = -1

                try:
                    size = int(inode.i_size)
                except Exception:
                    size = -1

                yield 0, (
                    major,
                    minor,
                    format_hints.Hex(raw_dev),
                    format_hints.Hex(inode_addr),
                    format_hints.Hex(mapping_addr),
                    nrpages,
                    size,
                )

                current = self.ptr_value(inode.i_sb_list.next)

            except Exception:
                # Tiếp tục bằng list_head hiện tại nếu inode bị smear.
                node = kernel.object(
                    object_type="list_head",
                    offset=current,
                    absolute=True,
                )
                current = self.ptr_value(node.next)

    def run(self):
        return renderers.TreeGrid(
            [
                ("Major", int),
                ("Minor", int),
                ("RawDev", format_hints.Hex),
                ("Inode", format_hints.Hex),
                ("Mapping", format_hints.Hex),
                ("NrPages", int),
                ("Size", int),
            ],
            self._generator(),
        )
