# freebsd-install-on-zfs-lite

[Ansible Galaxy](https://galaxy.ansible.com/click0/freebsd_install_on_zfs_lite/) 

FreeBSD. Installing a FreeBSD system on the root with ZFS from MfsBSD running in rescue mode.  

Feel free to [share your feedback and report issues](https://github.com/click0/ansible-freebsd-install-on-zfs-lite/issues).  
[Contributions are welcome](https://github.com/firstcontributions/first-contributions).  

## Synopsis

This role acts as a runner for the single [`gozfs.sh` script](https://github.com/click0/FreeBSD-install-scripts/blob/master/gozfs.sh).  
(That's why there is `lite` in the role name too)  
The role expects [MfsBSD](https://mfsbsd.vx.sk) as `standard` to be already running on the remote host (`mini` is an insufficient set of packages, `se` is oversized by the FreeBSD archives).  
The role installs the `python3` package (when missing) and uploads `gozfs.sh` to the host.  
The bundled script is **v2.23** and covers every sector size through the
`fiozl_ashift_disk` option (the former separate `gozfs_512b.sh` has been
merged in):
- `4k` (default) / `8k` — advanced-format disks. The ZFS partition is wrapped
  in a `gnop` device to force the pool ashift.
- `512b` — disks with native 512-byte sectors. No `gnop` wrapper, no `gpart`
  alignment override (`vfs.zfs.min_auto_ashift=12`).

The script does the following:  
- clears the disks specified in the script arguments.
- creates a ZFS pool and partition structure (BIOS, UEFI or hybrid layout).
- creates a Boot-Environment-aware root: `<pool>/ROOT/default` is mounted as `/`
  and registered as `bootfs`, ready to be cloned by `bectl`.
- optionally creates an aes-256-gcm encrypted dataset `<pool>/encrypted`
  (OpenZFS native encryption, `keylocation=prompt`).
- unpacks FreeBSD archives from the specified FTP/http/https host
  (optionally including debug sets: `base-dbg`, `lib32-dbg`, `kernel-dbg`).
- makes initial network settings (DHCP or a static CIDR address) and starts `sshd`.
- writes the target system DNS servers (`fiozl_nameserver`, option `-N`).
- downloads ssh keys (you will have to provide your http/https addresses).
- sets the password `root`/`mfsroot123` (you can set your own password in the script arguments).
Then the role itself will reboot the remote host on its own and wait for `sshd`
of the installed system (port 22, checked from the controller).  
If the script fails, the play stops at once and shows the tail of its output
(the tmux session `Install_FreeBSD` stays open on the host for inspection).  

## Variables

See the `defaults/main.yml` and examples in vars.

### Selected variables

| Variable | Default | Description |
| --- | --- | --- |
| `fiozl_provider` | `[ada0]` | List of GEOM providers to install onto. Each item may be `disk` or `disk=label`. |
| `fiozl_poolname` | `zroot` | Name of the new zpool. A pool with the same name on a disk that is **not** in `fiozl_provider` stops the install (the import would be ambiguous): clear it with `zpool labelclear`, add the disk, or pick another name. |
| `fiozl_mode` | _auto_ | `stripe`, `mirror` (2+ disks), `raidz` (3+), `raid10` (even number, 4+). When empty: 1 disk - `stripe`, 4 disks - `raid10`, otherwise `mirror`. |
| `fiozl_swap_partition_size` | `512M` | Size of the per-disk freebsd-swap partition (`0` to skip). |
| `fiozl_zfs_partition_size` | _full disk_ | Size of the freebsd-zfs partition (accepts human sizes, e.g. `10G`). |
| `fiozl_ashift_disk` | `4k` | Disk sector handling: `4k` (default), `8k`, or `512b` (native 512-byte sectors, no `gnop`). Option `-a`. |
| `fiozl_ftphost` | 14.4-RELEASE | Source URL for `base/lib32/kernel/MANIFEST` archives. Old releases disappear from the mirrors — set the release you need. |
| `fiozl_distdir` | _empty_ | Local directory on MfsBSD with pre-fetched `*.txz` (nothing is downloaded then; a missing set is an error). |
| `fiozl_hostname` | `core.domain.com` | Hostname for the new system. |
| `fiozl_password` | `mfsroot123` | Initial root password on the installed system. Any characters are allowed; it is kept out of the Ansible log, but is visible in `ps` on the MfsBSD host while the script runs. |
| `fiozl_timezone` | `Europe/Kyiv` | Timezone link for `/etc/localtime`. |
| `fiozl_url_ssh_key_file` | `[]` | List of URLs of a plain `authorized_keys` file (mirrors: the first one that can be fetched is used). |
| `fiozl_url_ssh_key_dir` | `[]` | List of URLs of a directory with `key1.pub`..`key9.pub` (mirrors: the first one that yields a key is used). |
| `fiozl_file_zfs_skeleton` | _empty_ | Local skeleton script on the installer (see `templates/zfs_skeleton.example`), option `-z`. |
| `fiozl_url_file_zfs_skeleton` | _empty_ | Same idea, fetched over HTTP into `/tmp/zfs_skeleton.sh` and executed, option `-Z`. |
| `fiozl_gateway`, `fiozl_ip` | `auto` / _empty_ | Network of the installed system. The default `auto` keeps the live IP and gateway of the MfsBSD host as a **static** configuration (DNS servers are copied from MfsBSD unless `fiozl_nameserver` is set). Set `fiozl_gateway: 'DHCP'` for DHCP, or a gateway IP plus `fiozl_ip: addr/prefix` and `fiozl_iface`. |
| `fiozl_install_timeout` | `3600` | Seconds to wait for the installer script. |
| `fiozl_reboot_wait`, `fiozl_reboot_timeout` | `true` / `300` | Wait for the sshd banner after the reboot. Disable when the host is not reachable directly from the controller (bastion). The check cannot tell the installed system from the installer: if the machine boots MfsBSD again (CD/PXE/rescue still first in the boot order) the wait succeeds as well. |
| `fiozl_reboot_wait_host` | _empty_ | Address to wait for; default is the static `fiozl_ip`, else `ansible_host`. |
| `fiozl_reboot_wait_port` | _empty_ | Port to wait for; default is `22`, or `ansible_port` when the address is `ansible_host` (port forwarding). |

#### New options (gozfs.sh ≥ 2.20)

| Variable | Default | Description |
| --- | --- | --- |
| `fiozl_boot_mode` | `auto` | `bios`, `uefi`, `hybrid` or `auto` (detect via `machdep.bootmethod` / `/sys/firmware/efi`). `uefi`/`hybrid` create an 800 MB EFI System Partition per disk and install `loader.efi` to both `EFI/BOOT/BOOTX64.efi` and `EFI/FreeBSD/loader.efi`. Option `-B`. |
| `fiozl_install_debug` | `false` | When `true`, also unpacks `base-dbg.txz`, `lib32-dbg.txz`, `kernel-dbg.txz` (passes `-x` to the script). |
| `fiozl_iface` | _empty_ | Network interface for the installed system. Auto-detected when empty, but **required** when `fiozl_ip` is a static address. Option `-i`. |
| `fiozl_ip` | _empty_ | `''`/`DHCP` (DHCP), `auto` (reuse the live IP), or a static `addr/prefix` such as `10.0.0.101/24`. Option `-I`. To force DHCP set `fiozl_gateway: 'DHCP'`. |
| `fiozl_nameserver` | _empty_ | DNS servers for the target system, comma- or space-separated (e.g. `8.8.8.8,1.1.1.1`). Writes `/etc/resolv.conf` and `/etc/resolvconf.conf`. Option `-N`. When empty and the network is static, the resolvers of the MfsBSD host are copied. |
| `fiozl_encryption_mode` | `none` | `native` enables OpenZFS native encryption: extra dataset `<pool>/encrypted` is created with `encryption=aes-256-gcm`, `keyformat=passphrase`, `keylocation=prompt`. Requires a passphrase (see below). Option `-E`. |
| `fiozl_encrypt_passphrase` | _empty_ | **Literal** passphrase (at least 8 characters). If non-empty and `fiozl_encryption_mode == 'native'`, the role uploads it (mode `0600`, `no_log`) to `/root/.zfs_passphrase` on the MfsBSD host and feeds it to the script via `-e`. Store it with `ansible-vault`. |
| `fiozl_encrypt_passphrase_file` | _empty_ | Path **on the MfsBSD host** to a pre-placed passphrase file. Used as-is via `-e` when `fiozl_encrypt_passphrase` is empty. |

The created pool always uses a Boot-Environment-aware layout: `<pool>/ROOT/default`
is the active root and `bootfs`, ready for `bectl create`/`bectl activate`.

### Encryption: how it works

When `fiozl_encryption_mode: native` is set, `gozfs.sh`:

1. obtains the passphrase from one of (in priority order):
   - `-e <file>` (set automatically by this role from `fiozl_encrypt_passphrase`,
     or directly from `fiozl_encrypt_passphrase_file`),
   - the `ZFS_ENCRYPT_PASSPHRASE` environment variable,
   - an interactive `stty -echo` prompt (only when running the script by hand;
     the role refuses to start `native` mode without a passphrase);
2. creates `<poolname>/encrypted` with `aes-256-gcm`, mounted at `/encrypted`;
3. immediately switches the dataset to `keylocation=prompt` and removes the
   temporary keyfile, so no plaintext key stays on disk;
4. writes `zfskeys_enable="YES"` and `zfskeys_prompt_enable="YES"` to `rc.conf`.

The passphrase must be at least 8 characters.

The dataset is **not** part of the root filesystem, so the system boots without
it. `rc.d/zfskeys` asks for the passphrase on the console at boot only on
FreeBSD versions that support `zfskeys_prompt_enable`; on the others (14.4 and
older) unlock it by hand after boot:

```
zfs load-key -a && zfs mount -a
```

## Workflow

1) Install the role

```
shell> ansible-galaxy role install click0.freebsd_install_on_zfs_lite
```

2) Look variables, e.g. in `defaults/main.yml`

You can override them in the playbook and inventory.  

3) Create playbook and inventory

```
shell> cat install_freebsd_in_mfsbsd.yml

- hosts: MfsBSD_server
  gather_facts: false
  vars:
#    fiozl_hostname: 'YOURHOSTNAME'
#    fiozl_iface: 'vtnet0'
#    fiozl_ftphost: 'http://ftp.freebsd.org/pub/FreeBSD/releases/amd64/15.1-RELEASE/'

  roles:
    - click0.freebsd_install_on_zfs_lite

```

### Example: UEFI + native encryption + debug sets

```yaml
- hosts: MfsBSD_server
  gather_facts: false
  vars:
    fiozl_provider:
      - 'nvd0'
      - 'nvd1'
    fiozl_mode: 'mirror'
    fiozl_poolname: 'zroot'
    fiozl_hostname: 'host1.example.org'
    fiozl_boot_mode: 'uefi'
    fiozl_encryption_mode: 'native'
    fiozl_encrypt_passphrase: '{{ vault_zfs_passphrase }}'   # ansible-vault
    fiozl_install_debug: true
    fiozl_url_ssh_key_file:
      - 'https://example.org/keys/admin.pub'
  roles:
    - click0.freebsd_install_on_zfs_lite
```

### Example: disk with native 512-byte sectors

```yaml
- hosts: MfsBSD_server
  gather_facts: false
  vars:
    fiozl_ashift_disk: '512b'
    fiozl_provider:
      - 'ada0'
    fiozl_poolname: 'zroot'
  roles:
    - click0.freebsd_install_on_zfs_lite
```

Commented options you may need.

```
shell> cat hosts
[MfsBSD_server]
<MfsBSD_server-ip-or-fqdn>
[MfsBSD_server:vars]
executable = /usr/local/bin/bash
ansible_shell_type = csh
ansible_python_interpreter=/usr/local/bin/python3
# ansible_ssh_common_args='-o ProxyCommand="ssh -W %h:%p -q my-bastion-host"'
# or
# ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
```
## Dependencies

None.

## Further use

You may need [another role](https://galaxy.ansible.com/click0/mfsbsd_install_via_linux_lite/) that runs MfsBSD through a Linux host grub.  

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
