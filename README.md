# freebsd-install-on-zfs-lite

[Ansible Galaxy](https://galaxy.ansible.com/click0/freebsd_install_on_zfs_lite/)

Installs FreeBSD with a ZFS root on a server that is running [MfsBSD](https://mfsbsd.vx.sk) (rescue system in memory),
then reboots the server into the installed system.

Feel free to [share your feedback and report issues](https://github.com/click0/ansible-freebsd-install-on-zfs-lite/issues).  
[Contributions are welcome](https://github.com/firstcontributions/first-contributions).  

> **The role erases the disks listed in `fiozl_provider`.** Run it only against a host booted into MfsBSD.

## What it is for

MfsBSD runs from memory and leaves the disks free. This role turns such a host into an installed FreeBSD:
partitions, ZFS pool, base system, boot loader, network, ssh access. No questions are asked and no console is needed.

The role is a thin runner (hence `lite`) for one shell script,
[`gozfs.sh`](https://github.com/click0/FreeBSD-install-scripts/blob/master/gozfs.sh), bundled as **v2.24**.
The script does the installation; the role checks the variables, runs the script, watches it and reboots the host.

MfsBSD can be started from a CD, PXE, the provider's rescue mode, or from a running Linux with the role
[`mfsbsd_install_via_linux_lite`](https://galaxy.ansible.com/click0/mfsbsd_install_via_linux_lite/).

## What the role does

1. **Checks the variables** before the host is touched: pool mode against the number of disks, sector size, boot mode,
   the passphrase for encryption, the interface for a static address.
2. **Prepares MfsBSD**: installs `python3` and `bash-static` with `pkg` if they are missing (MfsBSD has no Python).
3. **Uploads** `gozfs.sh` and a small runner file with the command line. The runner is readable by root only,
   because the command line contains the root password; it is removed when the script ends.
4. **Runs the script in a tmux session** named `Install_FreeBSD`, so the installation survives a lost ssh connection
   and can be watched on the host with `tmux attach -t Install_FreeBSD`.
5. **Waits** until the script ends (`fiozl_install_timeout`, one hour by default).
6. **Checks the result.** If the script failed, the play stops and shows the last lines of its output;
   the tmux session stays open for inspection and the host is not rebooted.
7. **Reboots** the host.
8. **Waits for sshd** of the installed system from the control node.

## Requirements

**Control node**
- Ansible 2.11 or newer.
- Direct access to the ssh port of the host for the final check (or see `fiozl_reboot_wait*`).
- `sshpass`, if you log in to MfsBSD with a password.

**Host**
- MfsBSD, the `standard` edition (`mini` lacks the needed tools, `se` is oversized by the FreeBSD archives it carries).
- Login as root.
- Internet access: the FreeBSD package repository (for Python) and a FreeBSD mirror with the release archives.
  The archives can also be put on the host beforehand (`fiozl_distdir`).
- The disks from `fiozl_provider` exist and may be erased.
- The server boots from those disks after the installation. If MfsBSD came from a CD or PXE, change the boot order,
  otherwise the server starts MfsBSD again.

## What the script does on the host

### Disks

Every disk from `fiozl_provider` gets the same new GPT layout; everything that was on the disk is destroyed,
including the labels of old ZFS pools.

| Partition | Size | When | GPT label |
| --- | --- | --- | --- |
| `freebsd-boot` | 512 kB | boot mode `bios` or `hybrid` | `boot-<number>` |
| `efi` (FAT32) | 800 MB | boot mode `uefi` or `hybrid` | `efi-<label>` |
| `freebsd-swap` | `fiozl_swap_partition_size` | unless the size is `0` | `swap-<label>` |
| `freebsd-zfs` | `fiozl_zfs_partition_size`, by default the rest of the disk | always | `system-<label>` |

- `<label>` is the disk name, or your own if the disk is given as `disk=label`.
- The smallest disk sets the size of the ZFS partition on all disks.
- A small tail of each disk stays unused (`fiozl_offset_end_disk`), so that a replacement disk
  with a few sectors less still fits.
- Swap is not mirrored: each disk has its own swap partition, all of them are listed in `/etc/fstab`.
- The boot loader is installed on every disk, so the system starts from any of them.

### Pool

| `fiozl_mode` | Disks | Result |
| --- | --- | --- |
| `stripe` | 1 or more | No redundancy. |
| `mirror` | 2 or more | One mirror of all disks. |
| `raidz` | 3 or more | One RAID-Z1 group. |
| `raid10` | 4 or more, even | Mirrored pairs, striped. |
| _empty_ | | 1 disk - `stripe`, 4 disks - `raid10`, otherwise `mirror`. |

The pool is created with `compression=lz4`, `atime=off`, NFSv4 ACLs and a 50 MB reservation
(a full pool can still be cleaned up).

If a pool with the same name already exists on a disk that is **not** part of the installation, the script stops
before it creates anything: two pools with one name make the import ambiguous and the system could mount the wrong root.
Clear that disk (`zpool labelclear`), add it to `fiozl_provider`, or choose another `fiozl_poolname`.

### Datasets

The layout is ready for boot environments (`bectl`):

- `<pool>/ROOT/default` is the root filesystem and the `bootfs` of the pool.
- `/tmp`, `/usr/home`, `/usr/ports` (with `distfiles` and `packages`), `/usr/src`,
  `/var/audit`, `/var/crash`, `/var/log`, `/var/mail`, `/var/tmp` are separate datasets outside the boot environment,
  so they are shared by all boot environments.
- `/home` is a symlink to `usr/home`.

To use another set of datasets, give your own skeleton script: `fiozl_file_zfs_skeleton` (a file on the host)
or `fiozl_url_file_zfs_skeleton` (downloaded and executed). `templates/zfs_skeleton.example` is a starting point.
The root dataset is created before the skeleton runs.

### System

- The sets `base`, `lib32` and `kernel` from `fiozl_ftphost` are unpacked into the pool
  (with `fiozl_install_debug` also the `-dbg` sets).
- `/etc/rc.conf`: hostname, ZFS, network, `sshd`.
- `/boot/loader.conf`: ZFS root, console on both the screen and the serial port (115200).
  On a machine with 3 GB of memory or less the ZFS ARC is limited to 200 MB.
- Time zone, root password, `authorized_keys` of root from the given URLs.
- The marker `/root/gozfs.sh.completed`.

Not done: packages, users, firewall, updates. That is the job of your next playbook.

## The installed system

| | |
| --- | --- |
| Login | `root` with `fiozl_password` (default `mfsroot123`), and the ssh keys from `fiozl_url_ssh_key_*`. |
| sshd | Port 22. Root login and password authentication are **allowed**: change the password or tighten `sshd_flags` in `/etc/rc.conf`. |
| Host key | New. Remove the old one from `known_hosts`. |
| Python | None. The next playbook must start with the `raw` module. |
| IPv4 | See [Network](#network). |
| IPv6 | Router advertisements (SLAAC) on the interface. A static IPv6 address is not configured. |

## Network

| Settings | Result in the installed system |
| --- | --- |
| Defaults (`fiozl_gateway: auto`, `fiozl_ip` empty) | The address, mask and default gateway that MfsBSD has right now are written as a **static** configuration of the interface with the default route, even if MfsBSD got them from DHCP. |
| `fiozl_gateway: 'DHCP'` | DHCP on all network cards. |
| `fiozl_gateway: <ip>`, `fiozl_ip: <addr/prefix>`, `fiozl_iface: <name>` | Exactly this static configuration. `fiozl_iface` is required here. |

DNS servers: `fiozl_nameserver` if set; otherwise, with a static configuration, the resolvers of MfsBSD are copied;
with DHCP they come from the lease.

## Boot mode

`fiozl_boot_mode` is `auto` by default: the system is installed for the mode MfsBSD itself was booted in.

- `bios` - protective MBR and `gptzfsboot` in the `freebsd-boot` partition.
- `uefi` - `loader.efi` on the EFI System Partition, both as `EFI/BOOT/BOOTX64.efi` (the path every firmware tries)
  and as `EFI/FreeBSD/loader.efi`. No boot entry is written to the firmware.
- `hybrid` - both, for a disk that must start either way.

MfsBSD started by GRUB on a UEFI machine (`mfsbsd_install_via_linux_lite` with a small ESP) believes it was booted by BIOS.
`install_mfsbsd_iso.sh` 1.31+ leaves a hint for that case and `auto` follows it. In any other doubtful case set the mode explicitly.

## Sector size

| `fiozl_ashift_disk` | Pool | For |
| --- | --- | --- |
| `4k` (default) | `ashift=12` | Almost every modern disk, also those that report 512-byte sectors. |
| `8k` | `ashift=13` | SSDs with 8 kB pages. |
| `512b` | chosen by ZFS | Disks with native 512-byte sectors, when the smaller block is wanted. |

The sector size of a pool cannot be changed later.

## Encryption

`fiozl_encryption_mode: native` adds one encrypted dataset, `<pool>/encrypted` (OpenZFS native encryption, `aes-256-gcm`),
mounted at `/encrypted`. The root filesystem is **not** encrypted, so the server boots without anybody at the console.

- The passphrase (at least 8 characters) comes from `fiozl_encrypt_passphrase` (keep it in `ansible-vault`;
  the role uploads it to a root-only file) or from a file that is already on the host (`fiozl_encrypt_passphrase_file`).
- After the dataset is created it is switched to `keylocation=prompt` and the temporary key file is removed:
  the passphrase is not stored on the disks.
- After every boot the dataset is locked. FreeBSD versions whose `rc.d/zfskeys` knows `zfskeys_prompt_enable`
  ask for the passphrase on the console; on the others (14.4 and older) unlock it by hand:

```
zfs load-key -a && zfs mount -a
```

## If something goes wrong

| Symptom | Meaning | What to do |
| --- | --- | --- |
| The play stops at the variable check | The combination of variables cannot work. The host was not touched. | Read the message, fix the variables. |
| The play stops after the script, with its output | The script failed. The host is still in MfsBSD. | `tmux attach -t Install_FreeBSD` on the host for the full output. Fix the cause and run the role again: it starts from clean disks. |
| `A pool named ... exists on a disk that is not part of this install` | See [Pool](#pool). | Clear the disk, add it, or rename the pool. |
| The script does not end within `fiozl_install_timeout` | Slow mirror or slow disks. | Raise the timeout; the session keeps running, look into tmux. |
| The wait for sshd fails | The system did not boot, or came up with another address. | Look at the console. Check the boot order, `fiozl_boot_mode` and the network variables. |
| The wait succeeds but the host is MfsBSD again | The server did not boot from the disks. The check sees only an ssh banner and cannot tell the two systems apart. | Change the boot order. |

## Variables

The defaults are in `defaults/main.yml`. Only `fiozl_provider` usually has to be set.

**Disks and pool**

| Variable | Default | Description |
| --- | --- | --- |
| `fiozl_provider` | `[ada0]` | Disks to install onto: `disk` or `disk=label`. |
| `fiozl_poolname` | `zroot` | Name of the pool. |
| `fiozl_mode` | by number of disks | `stripe`, `mirror`, `raidz`, `raid10`. |
| `fiozl_swap_partition_size` | `512M` | Swap partition on each disk; `0` - none. |
| `fiozl_zfs_partition_size` | rest of the disk | Size of the ZFS partition, e.g. `10G`. |
| `fiozl_offset_end_disk` | `2048` | Sectors left unused at the end of each disk. |
| `fiozl_ashift_disk` | `4k` | `4k`, `8k`, `512b`. |
| `fiozl_boot_mode` | `auto` | `auto`, `bios`, `uefi`, `hybrid`. |
| `fiozl_file_zfs_skeleton` | _empty_ | Path on the host to your dataset skeleton script. |
| `fiozl_url_file_zfs_skeleton` | _empty_ | URL of such a script. |

**System**

| Variable | Default | Description |
| --- | --- | --- |
| `fiozl_ftphost` | FreeBSD 14.4-RELEASE, amd64 | URL of the directory with `base.txz`, `kernel.txz`, ... Old releases disappear from the mirrors: set the release you need. |
| `fiozl_distdir` | _empty_ | Directory on the host with the archives already in it. Nothing is downloaded then; a missing archive is an error. |
| `fiozl_install_debug` | `false` | Also unpack `base-dbg`, `lib32-dbg`, `kernel-dbg`. |
| `fiozl_hostname` | `core.domain.com` | Hostname. |
| `fiozl_timezone` | `Europe/Kyiv` | Time zone. |
| `fiozl_password` | `mfsroot123` | root password. Any characters. It is kept out of the Ansible log, but is visible in the process list of MfsBSD while the script runs. |
| `fiozl_url_ssh_key_file` | `[]` | URLs of an `authorized_keys` file. A list of mirrors: the first one that answers is used. |
| `fiozl_url_ssh_key_dir` | `[]` | URLs of a directory with `key1.pub` .. `key9.pub`. A list of mirrors as well. |

**Network**

| Variable | Default | Description |
| --- | --- | --- |
| `fiozl_gateway` | `auto` | `auto`, `DHCP` or the address of the gateway. |
| `fiozl_ip` | _empty_ | `addr/prefix` for a static address. |
| `fiozl_iface` | detected | Network interface. Required with a static `fiozl_ip`. |
| `fiozl_nameserver` | _empty_ | DNS servers, separated by commas or spaces. |

**Encryption**

| Variable | Default | Description |
| --- | --- | --- |
| `fiozl_encryption_mode` | `none` | `native` creates the encrypted dataset. |
| `fiozl_encrypt_passphrase` | _empty_ | The passphrase itself. |
| `fiozl_encrypt_passphrase_file` | _empty_ | Path on the host to a file with the passphrase; used when the previous variable is empty. |

**Run control**

| Variable | Default | Description |
| --- | --- | --- |
| `fiozl_install_timeout` | `3600` | Seconds to wait for the script. |
| `fiozl_reboot_wait` | `true` | Wait for sshd after the reboot. Turn off when the control node has no direct access to the host. |
| `fiozl_reboot_timeout` | `300` | Seconds to wait for sshd. |
| `fiozl_reboot_wait_host` | static `fiozl_ip`, else `ansible_host` | Address to wait for. |
| `fiozl_reboot_wait_port` | `22`; `ansible_port` when waiting on `ansible_host` | Port to wait for. |

## Usage

Install the role:

```
ansible-galaxy role install click0.freebsd_install_on_zfs_lite
```

A playbook: two disks in a mirror, the network as MfsBSD has it. Facts cannot be gathered on a host without Python:

```yaml
- hosts: MfsBSD_server
  gather_facts: false
  vars:
    fiozl_provider:
      - 'ada0'
      - 'ada1'
    fiozl_hostname: 'host1.example.org'
    fiozl_password: '{{ vault_root_password }}'
    fiozl_url_ssh_key_file:
      - 'https://example.org/keys/admin.pub'
  roles:
    - click0.freebsd_install_on_zfs_lite
```

An inventory:

```ini
[MfsBSD_server]
<MfsBSD_server-ip-or-fqdn>

[MfsBSD_server:vars]
ansible_user=root
ansible_password=mfsroot
executable = /usr/local/bin/bash
ansible_shell_type = csh
ansible_python_interpreter=/usr/local/bin/python3
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
# behind a bastion:
# ansible_ssh_common_args='-o ProxyCommand="ssh -W %h:%p -q my-bastion-host"'
```

- **Password.** MfsBSD is entered with a password (`mfsroot` unless it was changed), which needs `sshpass` on the control node.
- **Shell.** The login shell of root in MfsBSD is `csh`. `ansible_shell_type = csh` tells Ansible to build its commands for it;
  this is required at least when the control node is a FreeBSD host.
- **Python** is installed by the role under `/usr/local`.
- **Host key.** MfsBSD generates it at boot, hence the relaxed host key checking.

## Dependencies

None.

### License

BSD 3-Clause

### Author:

- Vladislav V. Prodan `<github.com/click0>`

### 🤝 Contributing

Contributions, issues and feature requests are welcome!<br>
Feel free to check [issues page](https://github.com/click0/ansible-freebsd-install-on-zfs-lite/issues).

### Show your support

Give a ⭐ if this project helped you!

<a href="https://www.buymeacoffee.com/click0" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-orange.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>
