from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements


class DmCryptProbe(interfaces.plugins.PluginInterface):
    """Traverse a device-mapper block device and inspect dm-crypt objects."""

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
                name="inode",
                description="Address of block-device struct inode",
            ),
        ]

    @staticmethod
    def ptr_value(value):
        try:
            return int(value)
        except Exception:
            try:
                return int(value.vol.offset)
            except Exception:
                return 0

    @staticmethod
    def describe(value):
        type_name = getattr(
            getattr(value, "vol", None),
            "type_name",
            type(value).__name__,
        )

        try:
            number = int(value)

            if number < 0:
                rendered = str(number)
            else:
                rendered = f"{number} (0x{number:x})"

            return f"{rendered} [{type_name}]"

        except Exception:
            try:
                return f"@0x{int(value.vol.offset):x} [{type_name}]"
            except Exception:
                return f"<unreadable> [{type_name}]"

    @staticmethod
    def type_members(kernel, type_name):
        try:
            template = kernel.get_type(type_name)
        except Exception:
            return None, {}

        members = getattr(
            getattr(template, "vol", None),
            "members",
            {},
        )

        return template, members

    def dump_layout(self, kernel, type_name):
        template, members = self.type_members(kernel, type_name)

        if template is None:
            yield 0, (
                f"layout:{type_name}",
                "<missing>",
                "Type unavailable in ISF",
            )
            return

        try:
            size = int(template.vol.size)
        except Exception:
            size = -1

        yield 0, (
            f"layout:{type_name}",
            "<size>",
            f"{size} (0x{size:x})" if size >= 0 else "unknown",
        )

        for name in sorted(
            members,
            key=lambda item: template.relative_child_offset(item),
        ):
            try:
                offset = template.relative_child_offset(name)
                value = f"offset={offset} (0x{offset:x})"
            except Exception as error:
                value = f"offset error: {error}"

            yield 0, (
                f"layout:{type_name}",
                name,
                value,
            )

    def dump_object(
        self,
        kernel,
        type_name,
        address,
        section=None,
    ):
        if not address:
            yield 0, (
                section or f"object:{type_name}",
                "<address>",
                "NULL",
            )
            return

        template, members = self.type_members(kernel, type_name)

        if template is None:
            yield 0, (
                section or f"object:{type_name}",
                "<address>",
                f"0x{address:x}; type unavailable",
            )
            return

        section = section or f"object:{type_name}"

        yield 0, (
            section,
            "<address>",
            f"0x{address:x}",
        )

        try:
            obj = kernel.object(
                object_type=type_name,
                offset=address,
                absolute=True,
            )
        except Exception as error:
            yield 0, (
                section,
                "<error>",
                str(error),
            )
            return

        for name in sorted(
            members,
            key=lambda item: template.relative_child_offset(item),
        ):
            try:
                value = getattr(obj, name)
                rendered = self.describe(value)
            except Exception as error:
                rendered = f"<error: {error}>"

            yield 0, (
                section,
                name,
                rendered,
            )

    @staticmethod
    def has_member(kernel, type_name, member_name):
        try:
            template = kernel.get_type(type_name)
            template.relative_child_offset(member_name)
            return True
        except Exception:
            return False

    def object_at(self, kernel, type_name, address):
        return kernel.object(
            object_type=type_name,
            offset=address,
            absolute=True,
        )

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        inode_addr = int(self.config["inode"])

        relevant_types = (
            "bdev_inode",
            "block_device",
            "gendisk",
            "mapped_device",
            "dm_table",
            "dm_target",
            "crypt_config",
            "crypto_skcipher",
            "crypto_tfm",
            "crypto_alg",
        )

        for type_name in relevant_types:
            yield from self.dump_layout(kernel, type_name)

        yield 0, (
            "chain",
            "blockdev_inode",
            f"0x{inode_addr:x}",
        )

        # struct bdev_inode contains the VFS inode and block_device.
        try:
            bdev_inode_type = kernel.get_type("bdev_inode")
            vfs_offset = bdev_inode_type.relative_child_offset(
                "vfs_inode"
            )
            bdev_inode_addr = inode_addr - vfs_offset

            yield 0, (
                "chain",
                "bdev_inode",
                f"0x{bdev_inode_addr:x}",
            )

            yield from self.dump_object(
                kernel,
                "bdev_inode",
                bdev_inode_addr,
            )

        except Exception as error:
            yield 0, (
                "chain",
                "bdev_inode_error",
                str(error),
            )
            return

        # Locate embedded struct block_device.
        try:
            bdev_offset = bdev_inode_type.relative_child_offset("bdev")
            bdev_addr = bdev_inode_addr + bdev_offset

            yield 0, (
                "chain",
                "block_device",
                f"0x{bdev_addr:x}",
            )

            yield from self.dump_object(
                kernel,
                "block_device",
                bdev_addr,
            )

            bdev = self.object_at(
                kernel,
                "block_device",
                bdev_addr,
            )

        except Exception as error:
            yield 0, (
                "chain",
                "block_device_error",
                str(error),
            )
            return

        # block_device -> gendisk
        try:
            disk_addr = self.ptr_value(bdev.bd_disk)

            yield 0, (
                "chain",
                "gendisk",
                f"0x{disk_addr:x}",
            )

            yield from self.dump_object(
                kernel,
                "gendisk",
                disk_addr,
            )

            disk = self.object_at(
                kernel,
                "gendisk",
                disk_addr,
            )

        except Exception as error:
            yield 0, (
                "chain",
                "gendisk_error",
                str(error),
            )
            return

        # For device-mapper disks, private_data is struct mapped_device *.
        try:
            mapped_device_addr = self.ptr_value(
                disk.private_data
            )

            yield 0, (
                "chain",
                "mapped_device",
                f"0x{mapped_device_addr:x}",
            )

            yield from self.dump_object(
                kernel,
                "mapped_device",
                mapped_device_addr,
            )

            mapped_device = self.object_at(
                kernel,
                "mapped_device",
                mapped_device_addr,
            )

        except Exception as error:
            yield 0, (
                "chain",
                "mapped_device_error",
                str(error),
            )
            return

        # Locate the active dm_table.
        table_addr = 0
        table_field = None

        for candidate in (
            "map",
            "table",
            "live_table",
            "active_table",
        ):
            if not self.has_member(
                kernel,
                "mapped_device",
                candidate,
            ):
                continue

            try:
                possible = self.ptr_value(
                    getattr(mapped_device, candidate)
                )
            except Exception:
                continue

            if possible:
                table_addr = possible
                table_field = candidate
                break

        yield 0, (
            "chain",
            "dm_table_field",
            str(table_field),
        )

        yield 0, (
            "chain",
            "dm_table",
            f"0x{table_addr:x}",
        )

        if not table_addr:
            return

        yield from self.dump_object(
            kernel,
            "dm_table",
            table_addr,
        )

        try:
            table = self.object_at(
                kernel,
                "dm_table",
                table_addr,
            )
        except Exception:
            return

        try:
            num_targets = int(table.num_targets)
        except Exception:
            num_targets = -1

        yield 0, (
            "chain",
            "num_targets",
            str(num_targets),
        )

        target_addr = 0

        for candidate in (
            "targets",
            "target",
        ):
            if not self.has_member(
                kernel,
                "dm_table",
                candidate,
            ):
                continue

            try:
                possible = self.ptr_value(
                    getattr(table, candidate)
                )
            except Exception:
                continue

            if possible:
                target_addr = possible
                break

        yield 0, (
            "chain",
            "dm_target_0",
            f"0x{target_addr:x}",
        )

        if not target_addr:
            return

        yield from self.dump_object(
            kernel,
            "dm_target",
            target_addr,
            section="object:dm_target[0]",
        )

        try:
            target = self.object_at(
                kernel,
                "dm_target",
                target_addr,
            )

            private_addr = self.ptr_value(
                target.private
            )

        except Exception as error:
            yield 0, (
                "chain",
                "target_private_error",
                str(error),
            )
            return

        yield 0, (
            "chain",
            "crypt_config",
            f"0x{private_addr:x}",
        )

        yield from self.dump_object(
            kernel,
            "crypt_config",
            private_addr,
        )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Section", str),
                ("Field", str),
                ("Value", str),
            ],
            self._generator(),
        )
