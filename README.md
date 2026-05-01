# freebsd-install-on-zfs-lite

[Ansible Galaxy](https://galaxy.ansible.com/click0/freebsd_install_on_zfs_lite/) 

FreeBSD. Installing a FreeBSD system on the root with ZFS from MfsBSD running in rescue mode.  

Feel free to [share your feedback and report issues](https://github.com/click0/ansible-freebsd-install-on-zfs-lite/issues).  
[Contributions are welcome](https://github.com/firstcontributions/first-contributions).  

## Synopsis

This role acts as a runner for a single [`gozfs.sh` script](https://github.com/click0/FreeBSD-install-scripts/blob/master/gozfs.sh).  
(That's why there is `lite` in the role name too)  
The role expects [MfsBSD](https://mfsbsd.vx.sk) as `standard` to be already running on the remote host (`mini` is an insufficient set of packages, `se` is oversized by the FreeBSD archives).  
The role installs the python2 package and uploads the script `gozfs.sh` to host.  
The bundled `files/gozfs.sh` is **v1.60** and supports 512b/4k/8k ashift natively, so the
external `gozfs_512b.sh` script is no longer required (set `fiozl_ashift_disk: '512b'`).  
The script does the following:  
- clears the disks specified in the script arguments.
- creates a ZFS pool and partition structure (BIOS, UEFI or hybrid layout).
- creates a Boot-Environment-aware root: `<pool>/ROOT/default` is mounted as `/`
  and registered as `bootfs`, ready to be cloned by `bectl`.
- optionally creates an aes-256-gcm encrypted dataset `<pool>/encrypted`
  (OpenZFS native encryption, unlocked at boot via the `zfskeys` rc service).
- unpacks FreeBSD archives from the specified FTP/http/https host
  (optionally including debug sets: `base-dbg`, `lib32-dbg`, `kernel-dbg`).
- makes initial network settings and starts `sshd`.
- downloads ssh keys (you will have to provide your http/https addresses).
- sets the password `root`/`mfsroot123` (you can set your own password in the script arguments).
Then the role itself will reboot the remote host on its own.  

## Variables

See the `defaults/main.yml` and examples in vars.

### Selected variables

| Variable | Default | Description |
| --- | --- | --- |
| `fiozl_provider` | `[ada0]` | List of GEOM providers to install onto. Each item may be `disk` or `disk=label`. |
| `fiozl_poolname` | `zroot` | Name of the new zpool. |
| `fiozl_mode` | _auto_ | `stripe`, `mirror`, `raidz`, `raid10` (auto-picked from disk count when empty). |
| `fiozl_swap_partition_size` | `512M` | Size of the per-disk freebsd-swap partition (`0` to skip). |
| `fiozl_zfs_partition_size` | _full disk_ | Size of the freebsd-zfs partition. |
| `fiozl_ashift_disk` | `4k` | One of `512b`, `4k`, `8k`. |
| `fiozl_ftphost` | 15.0-RELEASE | Source URL for `base/lib32/kernel/MANIFEST` archives. |
| `fiozl_distdir` | _empty_ | Local directory on MfsBSD with pre-fetched `*.txz`. |
| `fiozl_hostname` | `core.domain.com` | Hostname for the new system. |
| `fiozl_password` | `mfsroot123` | Initial root password on the installed system. |
| `fiozl_timezone` | `Europe/Kyiv` | Timezone link for `/etc/localtime`. |
| `fiozl_url_ssh_key_file` | _list of urls_ | Plain `authorized_keys` URLs to fetch. |
| `fiozl_url_ssh_key_dir` | _list of urls_ | Directories on the web with `key1.pub`..`key9.pub`. |
| `fiozl_file_zfs_skeleton` | _empty_ | Local skeleton script (see `templates/zfs_skeleton.example`). |
| `fiozl_url_file_zfs_skeleton` | _empty_ | Same idea, fetched over HTTP. |
| `fiozl_gateway`, `fiozl_ip` | `auto` / _empty_ | Static network override; otherwise DHCP. |

#### New options (gozfs.sh ≥ 1.60)

| Variable | Default | Description |
| --- | --- | --- |
| `fiozl_boot_mode` | `auto` | `bios`, `uefi`, `hybrid` or `auto` (detect via `machdep.bootmethod` / `/sys/firmware/efi`). `uefi`/`hybrid` create an 800 MB EFI System Partition per disk and install `loader.efi` to both `EFI/BOOT/BOOTX64.efi` and `EFI/FreeBSD/loader.efi`. |
| `fiozl_encryption_mode` | `none` | `native` enables OpenZFS native encryption: extra dataset `<pool>/encrypted` is created with `encryption=aes-256-gcm`, `keyformat=passphrase`, `keylocation=prompt`. The `zfskeys_enable="YES"` line is added to `rc.conf` so the system prompts on boot. |
| `fiozl_encrypt_passphrase` | _empty_ | **Literal** passphrase. If non-empty and `fiozl_encryption_mode == 'native'`, the role uploads it (mode `0600`) to the MfsBSD host and feeds it to the script via `-e`. Mark `no_log: true` and/or store with `ansible-vault`. |
| `fiozl_encrypt_passphrase_file` | _empty_ | Path **on the MfsBSD host** to a pre-placed passphrase file. Used as-is when `fiozl_encrypt_passphrase` is empty. |
| `fiozl_install_debug` | `false` | When `true`, also unpacks `base-dbg.txz`, `lib32-dbg.txz`, `kernel-dbg.txz` (passes `-x` to the script). |
| `fiozl_ashift_disk: '512b'` | _-_ | Replacement for the old `gozfs_512b.sh` script (no `gnop` wrapper, no 4k alignment override). |

The created pool always uses a Boot-Environment-aware layout: `<pool>/ROOT/default`
is the active root and `bootfs`, ready for `bectl create`/`bectl activate`.

### Encryption: how it works

When `fiozl_encryption_mode: native` is set, `gozfs.sh`:

1. writes the passphrase from one of (in priority order):
   - `-e <file>` (set automatically by this role from `fiozl_encrypt_passphrase`),
   - the `ZFS_ENCRYPT_PASSPHRASE` environment variable,
   - an interactive `stty -echo` prompt (only useful when running the script by hand);
2. creates `<poolname>/encrypted` with `aes-256-gcm`, mounted at `/encrypted`;
3. immediately switches the dataset to `keylocation=prompt` so no plaintext key
   stays on disk;
4. enables `zfskeys_enable="YES"` in `rc.conf` so the key is requested at boot.

The passphrase must be at least 8 characters.

## Workflow

1) Install the role

```
shell> ansible-galaxy role install click0.freebsd_install_on_zfs_lite
```

2) Look variables, e.g. in `defaults/main.yml`

You can override them in the playbook and inventory.  

4) Create playbook and inventory

```
shell> cat install_freebsd_in_mfsbsd.yml

- hosts: MfsBSD_server
  gather_facts: false
  vars:
#  fiozl_mfsbsd_version: '12.2' # or 12
#  fiozl_hostname: 'YOURHOSTNAME'
#  fiozl_iface_list: 'vtnet0 fxp0 em0'
#  fiozl_hostname: 'vb-12-3.2'  # test name for DHCP  # look Inventory

  roles:
    - click0.freebsd-install-on-zfs-lite

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
    - click0.freebsd-install-on-zfs-lite
```

Commented options you may need.

```
shell> cat hosts
[MfsBSD_server]
<MfsBSD_server-ip-or-fqdn>
[MfsBSD_server:vars]
executable = /usr/local/bin/bash
ansible_shell_type = csh
ansible_python_interpreter=/usr/bin/python2
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
