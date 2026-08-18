[USAGE.md](https://github.com/user-attachments/files/31175857/USAGE.md)
# Volatility3 Linux Helper Plugins

This repository contains four custom Volatility3 Linux helper plugins for CTF and memory forensics workflows.

## Plugin List

| Plugin | Purpose |
|---|---|
| `linux.bdevinodes` | Lists Linux block-device inodes and maps major:minor numbers to kernel inode addresses. |
| `linux.dmcryptprobe` | Starts from a block-device inode and inspects device-mapper / dm-crypt runtime objects. |
| `linux.cryptconfigdump` | Dumps a selected kernel virtual-address range, usually after a `crypt_config` address is known. |
| `linux.keyringdump` | Finds a Linux kernel key by exact type/description and dumps its payload. |

---

## 1. `linux.bdevinodes`

### Purpose

Use this plugin to list block-device inodes from kernel memory.

This is useful when you know a block device by major:minor number, for example `252:0`, and need the kernel inode address of that block device.

Typical use case:

```text
mountinfo shows active mapper: 252:0
bdevinodes maps 252:0 -> block-device inode address
```

### Syntax

```bash
vol -f <memory_image> linux.bdevinodes
```

Example:

```bash
vol -f memory.elf linux.bdevinodes
```

### Important Output

```text
Major
Minor
Inode
Mapping
Size
```

The important value is `Inode`.

Example:

```text
Major  Minor  Inode
252    0      0x8a733676a470
```

That inode address can be passed to `linux.dmcryptprobe`.

---

## 2. `linux.dmcryptprobe`

### Purpose

Use this plugin to inspect an active device-mapper / dm-crypt block device.

It starts from a block-device inode address and walks kernel structures related to device-mapper and dm-crypt.

Typical use case:

```text
bdevinodes gives inode address of dm-0
dmcryptprobe uses that inode to inspect dm-crypt runtime state
```

### Syntax

```bash
vol -f <memory_image> linux.dmcryptprobe --inode <block_device_inode>
```

Example:

```bash
vol -f memory.elf linux.dmcryptprobe --inode 0x8a733676a470
```

### Important Output

Useful output may include:

```text
crypt_config address
cipher
key size
IV mode / IV offset
data offset
sector size
backing device
key reference
```

This plugin is mainly used to recover dm-crypt runtime parameters.

---

## 3. `linux.cryptconfigdump`

### Purpose

Use this plugin to dump a specific kernel virtual-address range.

It is commonly used after `linux.dmcryptprobe` has found a `crypt_config` address.

This plugin does not search for `crypt_config` by itself. It only dumps the memory range provided by the user.

Typical use case:

```text
dmcryptprobe finds crypt_config address
cryptconfigdump dumps that address range to a file
```

### Syntax

```bash
vol -f <memory_image> -o <output_directory> linux.cryptconfigdump \
  --address <kernel_address> \
  --length <dump_length>
```

Example:

```bash
mkdir -p cryptconfig_dump

vol -f memory.elf -o cryptconfig_dump linux.cryptconfigdump \
  --address 0x8a729bd10400 \
  --length 0x800
```

### Important Output

The plugin writes the dumped memory range into the output directory.

Useful follow-up commands:

```bash
find cryptconfig_dump -type f -printf '%s\t%p\n'
strings -a cryptconfig_dump/* | head
xxd cryptconfig_dump/* | head
```

---

## 4. `linux.keyringdump`

### Purpose

Use this plugin to find a Linux kernel key by exact type/description and dump its payload.

This is useful when another analysis step reveals a key description or key reference, such as a dm-crypt key description.

This plugin does not dump all keys by default. It requires an exact `--description`.

Typical use case:

```text
dmcryptprobe reveals a dm-crypt key description/reference
keyringdump searches for that exact key and dumps its payload
```

### Syntax

```bash
vol -f <memory_image> -o <output_directory> linux.keyringdump \
  --description <key_description> \
  --key_type <key_type> \
  --expected_size <bytes>
```

`--key_type` is optional and defaults to `logon`.

`--expected_size` is optional and defaults to `64`.

Example:

```bash
mkdir -p keys

vol -f memory.elf -o keys linux.keyringdump \
  --description 'dm-crypt:dev_volume' \
  --key_type logon \
  --expected_size 64
```

If the description already includes the `logon:` prefix, the plugin accepts that form too.

### Important Output

The plugin writes the matching key payload into the output directory.

List dumped files by size:

```bash
find keys -type f -printf '%s\t%p\n' | sort -n
```

A dumped key should be treated as a candidate until verified.

---

## Recommended dm-crypt Workflow

```text
1. Identify the active dm-crypt mapper and its major:minor number.
2. Run linux.bdevinodes to get the mapper's block-device inode address.
3. Run linux.dmcryptprobe with that inode to inspect dm-crypt runtime state.
4. If needed, run linux.cryptconfigdump to dump the crypt_config memory range.
5. If a key description/reference is known, run linux.keyringdump to dump the matching key payload.
6. Verify any candidate key and config before trusting the result.
```


