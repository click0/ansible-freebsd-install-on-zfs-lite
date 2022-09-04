# freebsd-install-on-zfs-lite

[Ansible Galaxy](https://galaxy.ansible.com/click0/freebsd_install_on_zfs_lite/) 

FreeBSD. Installing a FreeBSD system on the root with ZFS from MfsBSD running in rescue mode.  

Feel free to [share your feedback and report issues](https://github.com/click0/ansible-freebsd-install-on-zfs-lite/issues).  
[Contributions are welcome](https://github.com/firstcontributions/first-contributions).  

## Synopsis

This role acts as a runner for a single [`go11_4k.sh` script](https://github.com/click0/FreeBSD-install-scripts/blob/master/go11_4k.sh).  
(That's why there is `lite` in the role name too)  
The role expects [MfsBSD](https://mfsbsd.vx.sk) as `standard` to be already running on the remote host (`mini` is an insufficient set of packages, `se` is oversized by the FreeBSD archives).  
The role installs the python2 package and uploads the script `go11_4k.sh` to host.  
If you _really need_ to create a ZFS pool with block devices with a block of 512 bytes, then use the [`go11.sh` script](https://github.com/click0/FreeBSD-install-scripts/blob/master/go11.sh).  
The script does the following:  
- clears the disks specified in the script arguments.
- creates a ZFS pool and partition structure.
- unpacks FreeBSD archives from the specified FTP/http/https host.
- makes initial network settings and starts `sshd`.
- downloads ssh keys (you will have to provide your http/https addresses).
- sets the password `root`/`mfsroot123` (you can set your own password in the script arguments).
Then the role itself will reboot the remote host on its own.  

## Variables

See the `defaults/main.yml` and examples in vars.

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

- hosts: MfsMSD_server
  gather_facts: false
  vars:
#  fiozl_mfsbsd_version: '12.2' # or 12
#  fiozl_hostname: 'YOURHOSTNAME'
#  fiozl_iface_list: 'vtnet0 fxp0 em0'
#  fiozl_hostname: 'vb-12-3.2'  # test name for DHCP  # look Inventory

  roles:
    - click0.freebsd-install-on-zfs-lite

```

Commented options you may need.

```
shell> cat hosts
[MfsMSD_server]
<MfsMSD_server-ip-or-fqdn>
[MfsMSD_server:vars]
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
