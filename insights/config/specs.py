#!/usr/bin/env python
"""
Specification for data collected by Insights.

These specifications represent the data that is collected by the insights client
and processed by the parsers and combiners in insights. The client must also implement
the spec before the data will be collected so don't just assume that data for all
specs listed here are collected.
"""

from insights.config import SimpleFileSpec, PatternSpec, CommandSpec, format_rpm, json_format, First, All, NoneGroup
from insights.config import DockerHostSimpleFileSpec, DockerHostPatternSpec, DockerHostCommandSpec


static_specs = {
    "autofs.conf"               : SimpleFileSpec("etc/autofs.conf"),
    "auditd.conf"               : SimpleFileSpec("etc/audit/auditd.conf"),
    "blkid"                     : First([CommandSpec("/sbin/blkid -c /dev/null"),
                                    SimpleFileSpec("run/blkid"),
                                    SimpleFileSpec("sos_commands/filesys/blkid")]),
    "bond"                      : PatternSpec(r"proc/net/bonding/bond.*"),
    "brctl_show"                : CommandSpec("/usr/sbin/brctl show"),
    "candlepin.log"             : First([SimpleFileSpec(r"var/log/candlepin/candlepin.log", large_content=True),
                                    SimpleFileSpec(r"sos_commands/foreman/foreman-debug/var/log/candlepin/candlepin.log", large_content=True)]),
    "candlepin_error_log"       : First([SimpleFileSpec(r"var/log/candlepin/error.log", large_content=True),
                                    SimpleFileSpec(r"sos_commands/foreman/foreman-debug/var/log/candlepin/error.log", large_content=True)]),
    "catalina.out"              : First([PatternSpec(r"var/log/tomcat.*/catalina\.out", large_content=True),
                                    PatternSpec(r"tomcat-logs/tomcat.*/catalina\.out", large_content=True)]),
    "cciss"                     : PatternSpec(r"proc/driver/cciss/cciss.*"),
    "ceilometer_central_log"    : SimpleFileSpec("var/log/ceilometer/central.log", large_content=True),
    "ceilometer_collector_log"  : SimpleFileSpec("var/log/ceilometer/collector.log", large_content=True),
    "ceilometer.conf"           : SimpleFileSpec("etc/ceilometer/ceilometer.conf"),
    "ceph_config_show"          : CommandSpec("/usr/bin/ceph daemon {ceph_socket_files} config show", ceph_socket_files=r"\S+"),
    "ceph_df_detail"            : CommandSpec("/usr/bin/ceph df detail -f json-pretty"),
    "ceph_health_detail"        : CommandSpec("/usr/bin/ceph health detail -f json-pretty"),
    "ceph_osd_tree"             : CommandSpec("/usr/bin/ceph osd tree -f json-pretty"),
    "ceph_osd_dump"             : CommandSpec("/usr/bin/ceph osd dump -f json-pretty"),
    "ceph_osd_df"               : CommandSpec("/usr/bin/ceph osd df -f json-pretty"),
    "ceph_osd_ec_profile_get"   : CommandSpec("/usr/bin/ceph osd erasure-code-profile get {ceph_osd_ec_profile_ls} -f json-pretty ", ceph_osd_ec_profile_ls=r"\S+"),
    "ceph_osd.log"              : PatternSpec(r"var/log/ceph/ceph-osd.*\.log$", large_content=True),
    "ceph_s"                    : CommandSpec("/usr/bin/ceph -s -f json-pretty"),
    "ceph_v"                    : CommandSpec("/usr/bin/ceph -v"),
    "certificates_enddate"      : CommandSpec("/usr/bin/find /etc/origin/node /etc/origin/master /etc/pki -type f -exec /usr/bin/openssl x509 -noout -enddate -in '{}' \; -exec echo 'FileName= {}' \;"),
    "cinder_volume.log"         : SimpleFileSpec("var/log/cinder/volume.log", large_content=True),
    "chkconfig"                 : CommandSpec("/sbin/chkconfig --list"),
    "chrony.conf"               : SimpleFileSpec("etc/chrony.conf"),
    "chronyc_sources"           : CommandSpec("/usr/bin/chronyc sources"),
    "cib.xml"                   : SimpleFileSpec("var/lib/pacemaker/cib/cib.xml"),
    "cinder.conf"               : SimpleFileSpec("etc/cinder/cinder.conf"),
    "cluster.conf"              : SimpleFileSpec("etc/cluster/cluster.conf"),
    "cmdline"                   : SimpleFileSpec("proc/cmdline"),
    "cobbler_settings"          : First([SimpleFileSpec("etc/cobbler/settings"),
                                    SimpleFileSpec("conf/cobbler/settings")]),
    "cobbler_modules.conf"      : First([SimpleFileSpec("etc/cobbler/modules.conf"),
                                    SimpleFileSpec("conf/cobbler/modules.conf")]),
    "corosync"                  : SimpleFileSpec("etc/sysconfig/corosync"),
    "cpuinfo"                   : First([SimpleFileSpec("proc/cpuinfo"),
                                    SimpleFileSpec("cpuinfo")]),
    "current_clocksource"       : SimpleFileSpec("sys/devices/system/clocksource/clocksource0/current_clocksource"),
    "date"                      : CommandSpec("/bin/date"),
    "date_iso"                  : CommandSpec("/bin/date --iso-8601=seconds"),
    "date_utc"                  : CommandSpec("/bin/date --utc"),
    "dcbtool_gc_dcb"            : CommandSpec("/sbin/dcbtool gc {iface} dcb", iface=r"\S+"),
    "df_-al"                    : First([CommandSpec("/bin/df -al"),
                                    SimpleFileSpec("diskinfo")]),
    "df_-alP"                   : CommandSpec("/bin/df -alP"),
    "df_-li"                    : CommandSpec("/bin/df -li"),
    "dig"                       : CommandSpec("/usr/bin/dig +dnssec . DNSKEY"),
    "dig_dnssec"                : CommandSpec("/usr/bin/dig +dnssec . SOA"),
    "dig_edns"                  : CommandSpec("/usr/bin/dig +edns=0 . SOA"),
    "dig_noedns"                : CommandSpec("/usr/bin/dig +noedns . SOA"),
    "dirsrv"                    : SimpleFileSpec("etc/sysconfig/dirsrv"),
    "dirsrv_access"             : PatternSpec("var/log/dirsrv/.*/access"),
    "dirsrv_errors"             : PatternSpec("var/log/dirsrv/.*/errors"),
    "display_java"              : CommandSpec("/usr/sbin/alternatives --display java"),
    "dmesg"                     : CommandSpec("/bin/dmesg", large_content=True),
    "dmidecode"                 : CommandSpec("/usr/sbin/dmidecode"),
    "docker_container_inspect"  : DockerHostCommandSpec("/usr/bin/docker inspect --type=container {docker_containers}", docker_containers=r"\S+"),
    "docker_image_inspect"      : DockerHostCommandSpec("/usr/bin/docker inspect --type=image {docker_images}", docker_images=r"\S+"),
    "docker_host_machine-id"    : DockerHostSimpleFileSpec("etc/redhat-access-insights/machine-id"),
    "docker_info"               : CommandSpec("/usr/bin/docker info"),
    "docker_list_containers"    : CommandSpec("/usr/bin/docker ps --all --no-trunc"),
    "docker_list_images"        : CommandSpec("/usr/bin/docker images --all --no-trunc --digests"),
    "docker_network"            : DockerHostSimpleFileSpec("etc/sysconfig/docker-network"),
    "docker_storage"            : DockerHostSimpleFileSpec("etc/sysconfig/docker-storage"),
    "docker_storage_setup"      : DockerHostSimpleFileSpec("etc/sysconfig/docker-storage-setup"),
    "docker_sysconfig"          : DockerHostSimpleFileSpec("etc/sysconfig/docker"),
    "dumpe2fs-h"                : CommandSpec("/sbin/dumpe2fs -h {dumpdev}", dumpdev=r"\S+"),
    "engine.log"                : SimpleFileSpec("var/log/ovirt-engine/engine.log", large_content=True),
    "etc_journald.conf"         : PatternSpec(r"etc/systemd/journald\.conf"),
    "etc_journald.conf.d"       : PatternSpec(r"etc/systemd/journald.conf.d/.+\.conf"),  # note that usr_journald.conf.d also exists
    "ethtool"                   : CommandSpec("/sbin/ethtool {iface}", iface=r"[^-]\S+"),
    "ethtool-a"                 : CommandSpec("/sbin/ethtool -a {iface}", iface=r"\S+"),
    "ethtool-c"                 : CommandSpec("/sbin/ethtool -c {iface}", iface=r"\S+"),
    "ethtool-g"                 : CommandSpec("/sbin/ethtool -g {iface}", iface=r"\S+"),
    "ethtool-i"                 : CommandSpec("/sbin/ethtool -i {iface}", iface=r"\S+"),
    "ethtool-k"                 : CommandSpec("/sbin/ethtool -k {iface}", iface=r"\S+"),
    "ethtool-S"                 : CommandSpec("/sbin/ethtool -S {iface}", iface=r"\S+"),
    "exim.conf"                 : SimpleFileSpec("etc/exim.conf"),
    "facter"                    : First([CommandSpec("/usr/bin/facter"),
                                    SimpleFileSpec("facts")]),
    "fc-match"                  : CommandSpec("/usr/bin/fc-match -sv 'sans:regular:roman' family fontformat"),
    "fdisk-l"                   : CommandSpec("/sbin/fdisk -l"),
    "fdisk-l-sos"               : PatternSpec(r"sos_commands/filesys/fdisk_-l_.+"),
    "foreman_satellite.log"     : First([SimpleFileSpec("var/log/foreman-installer/satellite.log", large_content=True),
                                    SimpleFileSpec("sos_commands/foreman/foreman-debug/var/log/foreman-installer/satellite.log", large_content=True)]),
    "foreman_production.log"    : First([SimpleFileSpec("var/log/foreman/production.log", large_content=True),
                                    SimpleFileSpec("sos_commands/foreman/foreman-debug/var/log/foreman/production.log", large_content=True)]),
    "foreman_proxy_conf"        : First([SimpleFileSpec("etc/foreman-proxy/settings.yml"),
                                    SimpleFileSpec("sos_commands/foreman/foreman-debug/etc/foreman-proxy/settings.yml")]),
    "foreman_proxy.log"         : First([SimpleFileSpec("var/log/foreman-proxy/proxy.log", large_content=True),
                                    SimpleFileSpec("sos_commands/foreman/foreman-debug/var/log/foreman-proxy/proxy.log", large_content=True)]),
    "fstab"                     : SimpleFileSpec("etc/fstab"),
    "galera.cnf"                : SimpleFileSpec("etc/my.cnf.d/galera.cnf"),
    'getcert_list'              : First([CommandSpec("/usr/bin/getcert list"),
                                    SimpleFileSpec("sos_commands/ipa/ipa-getcert_list")]),
    "getenforce"                : CommandSpec("/usr/sbin/getenforce"),
    "getsebool"                 : CommandSpec("/usr/sbin/getsebool -a"),
    "glance-api.conf"           : SimpleFileSpec("etc/glance/glance-api.conf"),
    "glance_api_log"            : SimpleFileSpec("var/log/glance/api.log", large_content=True),
    "glance-cache.conf"         : SimpleFileSpec("etc/glance/glance-cache.conf"),
    "glance-registry.conf"      : SimpleFileSpec("etc/glance/glance-registry.conf"),
    "grub.conf"                 : SimpleFileSpec("boot/grub/grub.conf"),
    "grub2.cfg"                 : SimpleFileSpec("boot/grub2/grub.cfg"),
    "grub2-efi.cfg"             : SimpleFileSpec("boot/efi/EFI/redhat/grub.cfg"),
    "grub_config_perms"         : CommandSpec("/bin/ls -l /boot/grub2/grub.cfg"),  # only RHEL7 and updwards
    "grub1_config_perms"        : CommandSpec("/bin/ls -l /boot/grub/grub.conf"),  # RHEL6
    "hammer_ping"               : CommandSpec("/usr/bin/hammer ping"),
    "haproxy_cfg"               : SimpleFileSpec("etc/haproxy/haproxy.cfg"),
    "heat-api.log"              : SimpleFileSpec("var/log/heat/heat-api.log", large_content=True),
    "heat.conf"                 : SimpleFileSpec("etc/heat/heat.conf"),
    "heat-engine.log"           : SimpleFileSpec("var/log/heat/heat-engine.log", large_content=True),
    "heat_crontab"              : CommandSpec("/usr/bin/crontab -l -u heat"),
    "hostname"                  : CommandSpec("/bin/hostname"),
    "hosts"                     : SimpleFileSpec("etc/hosts"),
    "hponcfg-g"                 : CommandSpec("/sbin/hponcfg -g"),
    "httpd_access_log"          : SimpleFileSpec("var/log/httpd/access_log", large_content=True),
    "httpd_conf"                : All([PatternSpec(r"etc/httpd/conf/httpd\.conf"),
                                    PatternSpec(r"etc/httpd/conf.d/.+\.conf")]),
    "httpd_conf_sos"            : NoneGroup([PatternSpec(r"conf/httpd/conf/httpd\.conf"),
                                    PatternSpec(r"conf/httpd/conf.d/.+\.conf")]),
    "httpd_error_log"           : SimpleFileSpec("var/log/httpd/error_log", large_content=True),
    "httpd_limits"              : CommandSpec("/bin/cat /proc/{httpd_pid}/limits", httpd_pid=r"\S+"),
    "httpd_ssl_access_log"      : SimpleFileSpec("var/log/httpd/ssl_access_log", large_content=True),
    "httpd_ssl_error_log"       : SimpleFileSpec("var/log/httpd/ssl_error_log", large_content=True),
    "httpd-V"                   : CommandSpec("/usr/sbin/httpd -V"),
    "ifcfg"                     : PatternSpec(r"etc/sysconfig/network-scripts/ifcfg-.*"),
    "ifconfig"                  : First([CommandSpec("/sbin/ifconfig -a"),
                                    SimpleFileSpec("ifconfig"),
                                    SimpleFileSpec("sos_commands/foreman/foreman-debug/ifconfig")]),
    "imagemagick_policy"        : All([PatternSpec(r"etc/ImageMagick/policy\.xml"),  # RHEL6, RHEL7
                                    PatternSpec(r"usr/lib64/ImageMagick-6.5.4/config/policy\.xml"),  # ImageMagick 6.5 on rhel-6 64bit.
                                    PatternSpec(r"usr/lib/ImageMagick-6.5.4/config/policy\.xml")]),  # ImageMagick 6.5 on rhel-6 32bit.
    "init.ora"                  : SimpleFileSpec("{ORACLE_HOME}/dbs/init.ora"),
    "initscript"                : NoneGroup([PatternSpec(r"etc/rc\.d/init\.d/.*")]),
    "installed-rpms"            : First([CommandSpec("/bin/rpm -qa --qf='%s'" % format_rpm(), multi_output=False),
                                    CommandSpec("/bin/rpm -qa --qf='%s'" % format_rpm(1), multi_output=False),
                                    CommandSpec("/bin/rpm -qa --qf='%s'" % format_rpm(3), multi_output=False),
                                    CommandSpec("/bin/rpm -qa --qf='%s'" % json_format()(), multi_output=False),
                                    SimpleFileSpec("installed-rpms"),
                                    SimpleFileSpec("installed_packages"),
                                    SimpleFileSpec("rpm-manifest")]),
    "interrupts"                : SimpleFileSpec("proc/interrupts"),
    "ip_addr"                   : First([CommandSpec("/sbin/ip addr"),
                                    SimpleFileSpec("sos_commands/networking/ip_address"),
                                    SimpleFileSpec("ip_a")]),
    "ip_route_show_table_all"   : CommandSpec("/sbin/ip route show table all"),
    "ipaupgrade_log"            : SimpleFileSpec("var/log/ipaupgrade.log"),
    "ipcs_s"                    : CommandSpec("/usr/bin/ipcs -s"),
    "ipcs_s_i"                  : CommandSpec("/usr/bin/ipcs -s -i {semid}", semid=r"\S+"),
    "iptables"                  : CommandSpec("/sbin/iptables-save"),
    "ip6tables"                 : CommandSpec("/sbin/ip6tables-save"),
    "iptables_permanent"        : SimpleFileSpec("etc/sysconfig/iptables"),
    "ip6tables_permanent"       : SimpleFileSpec("etc/sysconfig/ip6tables"),
    "ipv4_neigh"                : CommandSpec("/sbin/ip -4 neighbor show nud all"),
    "ipv6_neigh"                : CommandSpec("/sbin/ip -6 neighbor show nud all"),
    "iscsiadm_m_session"        : CommandSpec("/usr/sbin/iscsiadm -m session"),
    "journal_since_boot"        : SimpleFileSpec("sos_commands/logs/journalctl_--no-pager_--boot", large_content=True),
    "katello-service_status"    : CommandSpec("/usr/bin/katello-service status"),
    "kdump"                     : SimpleFileSpec("etc/sysconfig/kdump"),
    "kdump.conf"                : SimpleFileSpec("etc/kdump.conf"),
    "kexec_crash_loaded"        : SimpleFileSpec("sys/kernel/kexec_crash_loaded"),
    "kexec_crash_size"          : SimpleFileSpec("sys/kernel/kexec_crash_size"),
    "keystone.conf"             : SimpleFileSpec("etc/keystone/keystone.conf"),
    "keystone.log"              : SimpleFileSpec("var/log/keystone/keystone.log"),
    "keystone_crontab"          : CommandSpec("/usr/bin/crontab -l -u keystone"),
    "kerberos_kdc_log"          : SimpleFileSpec("var/log/krb5kdc.log"),
    "krb5"                      : All([PatternSpec(r"etc/krb5\.conf"), PatternSpec(r"etc/krb5.conf\.d/.*\.conf")]),
    "ksmstate"                  : SimpleFileSpec("sys/kernel/mm/ksm/run"),
    "lastupload"                : All([SimpleFileSpec("etc/redhat-access-insights/.lastupload"),
                                    SimpleFileSpec("etc/insights-client/.lastupload")]),
    "libkeyutils"               : CommandSpec("/usr/bin/find -L /lib /lib64 -name 'libkeyutils.so*'"),
    "libkeyutils_objdumps"      : CommandSpec('/usr/bin/find -L /lib /lib64 -name libkeyutils.so.1 -exec objdump -x "{}" \;'),
    "libvirtd.log"              : SimpleFileSpec("var/log/libvirt/libvirtd.log"),
    "limits_conf"               : All([PatternSpec("etc/security/limits\.conf"),
                                    PatternSpec(r"etc/security/limits.d/.*\.conf")]),
    "locale"                    : CommandSpec("/usr/bin/locale"),
    "localtime"                 : CommandSpec("/usr/bin/file -L /etc/localtime"),
    "lpstat_p"                  : CommandSpec("/usr/bin/lpstat -p"),
    "lsblk"                     : CommandSpec("/bin/lsblk"),
    "lsblk_pairs"               : CommandSpec("/bin/lsblk -P -o NAME,KNAME,MAJ:MIN,FSTYPE,MOUNTPOINT,LABEL,UUID,RA,RO,RM,MODEL,SIZE,STATE,OWNER,GROUP,MODE,ALIGNMENT,MIN-IO,OPT-IO,PHY-SEC,LOG-SEC,ROTA,SCHED,RQ-SIZE,TYPE,DISC-ALN,DISC-GRAN,DISC-MAX,DISC-ZERO"),
    "lscpu"                     : CommandSpec("/usr/bin/lscpu"),
    "lsinitrd_lvm.conf"         : All([CommandSpec("/sbin/lsinitrd -f /etc/lvm/lvm.conf"),
                                    CommandSpec("/usr/bin/lsinitrd -f /etc/lvm/lvm.conf")]),
    "lsmod"                     : CommandSpec("/sbin/lsmod"),
    "lspci"                     : CommandSpec("/sbin/lspci"),
    "lsof"                      : CommandSpec("/usr/sbin/lsof", large_content=True),
    "lssap"                     : CommandSpec("/usr/sap/hostctrl/exe/lssap"),
    "ls_boot"                   : CommandSpec("/bin/ls -lanR /boot"),
    "ls_docker_volumes"         : CommandSpec("/bin/ls -lanR /var/lib/docker/volumes"),
    "ls_dev"                    : CommandSpec("/bin/ls -lanR /dev"),
    "ls_disk"                   : CommandSpec("/bin/ls -lanR /dev/disk"),
    "ls_etc"                    : CommandSpec("/bin/ls -lanR /etc"),
    "ls_sys_firmware"           : CommandSpec("/bin/ls -lanR /sys/firmware"),
    "ls_var_log"                : CommandSpec("/bin/ls -la /var/log /var/log/audit"),
    "lvdisplay"                 : CommandSpec("/sbin/lvdisplay"),
    "lvm.conf"                  : SimpleFileSpec("etc/lvm/lvm.conf"),
    "lvs"                       : NoneGroup([CommandSpec('/sbin/lvs -a -o +lv_tags,devices --config="global{locking_type=0}"')]),
    "lvs_noheadings"            : CommandSpec("/sbin/lvs --nameprefixes --noheadings --separator='|' -a -o lv_name,lv_size,lv_attr,mirror_log,vg_name,devices,region_size,data_percent,metadata_percent --config=\"global{locking_type=0}\""),
    "mariadb.log"               : SimpleFileSpec("var/log/mariadb/mariadb.log", large_content=True),
    "mdstat"                    : SimpleFileSpec("proc/mdstat"),
    "meminfo"                   : First([SimpleFileSpec("proc/meminfo"),
                                    SimpleFileSpec("meminfo")]),
    "messages"                  : SimpleFileSpec("var/log/messages", large_content=True),
    "mlx4_port"                 : CommandSpec("/usr/bin/find /sys/bus/pci/devices/*/mlx4_port[0-9] -print -exec cat {} \;"),
    "modinfo"                   : CommandSpec("/usr/sbin/modinfo {module}", module=r"\S+"),
    "modprobe.conf"             : PatternSpec(r"etc/modprobe\.conf"),
    "modprobe.d"                : PatternSpec(r"etc/modprobe.d/.*\.conf"),
    "mongod_conf"               : All([SimpleFileSpec("etc/mongod.conf"),
                                    SimpleFileSpec("etc/mongodb.conf"),
                                    SimpleFileSpec("etc/opt/rh/rh-mongodb26/mongod.conf")]),
    "mount"                     : CommandSpec("/bin/mount"),
    "multicast_querier"         : CommandSpec("/usr/bin/find /sys/devices/virtual/net/ -name multicast_querier -print -exec cat {} \;"),
    "multipath.conf"            : SimpleFileSpec("etc/multipath.conf"),
    "multipath_-v4_-ll"         : CommandSpec("/sbin/multipath -v4 -ll"),
    "named-checkconf_p"         : CommandSpec("/usr/sbin/named-checkconf -p"),
    "netconsole"                : SimpleFileSpec("etc/sysconfig/netconsole"),
    "netstat"                   : CommandSpec("/bin/netstat -neopa"),
    "netstat_-agn"              : CommandSpec("/bin/netstat -agn"),
    "netstat-i"                 : CommandSpec("/bin/netstat -i"),
    "netstat-s"                 : CommandSpec("/bin/netstat -s"),
    "neutron.conf"              : SimpleFileSpec("etc/neutron/neutron.conf"),
    "neutron_ovs_agent_log"     : SimpleFileSpec("var/log/neutron/openvswitch-agent.log", large_content=True),
    "neutron_plugin.ini"        : SimpleFileSpec("etc/neutron/plugin.ini"),
    "neutron_server_log"        : SimpleFileSpec("var/log/neutron/server.log", large_content=True),
    "nfnetlink_queue"           : SimpleFileSpec("proc/net/netfilter/nfnetlink_queue"),
    "nfs_exports"               : SimpleFileSpec("etc/exports"),
    "nfs_exports.d"             : PatternSpec(r"etc/exports.d/.*\.exports"),
    "nova-api_log"              : SimpleFileSpec("var/log/nova/nova-api.log", large_content=True),
    "nova-compute.log"          : SimpleFileSpec("var/log/nova/nova-compute.log", large_content=True),
    "nova.conf"                 : SimpleFileSpec("etc/nova/nova.conf"),
    "nova_crontab"              : CommandSpec("/usr/bin/crontab -l -u nova"),
    "nscd.conf"                 : SimpleFileSpec("etc/nscd.conf"),
    "nsswitch.conf"             : SimpleFileSpec("etc/nsswitch.conf"),
    "ntp.conf"                  : SimpleFileSpec("etc/ntp.conf"),
    "ntpq_leap"                 : CommandSpec("/usr/sbin/ntpq -c 'rv 0 leap'"),
    "ntpq_pn"                   : CommandSpec("/usr/sbin/ntpq -pn"),
    "ntptime"                   : CommandSpec("/usr/sbin/ntptime"),
    "numeric_user_group_name"   : CommandSpec("/bin/grep -c '^[[:digit:]]' /etc/passwd /etc/group"),
    "openvswitch_server_log"    : SimpleFileSpec('var/log/openvswitch/ovsdb-server.log'),
    "openvswitch_daemon_log"    : SimpleFileSpec('var/log/openvswitch/ovs-vswitchd.log'),
    "os-release"                : SimpleFileSpec("etc/os-release"),
    'osa_dispatcher.log'        : First([SimpleFileSpec("var/log/rhn/osa-dispatcher.log", large_content=True),
                                    SimpleFileSpec("rhn-logs/rhn/osa-dispatcher.log", large_content=True)]),
    "ose_master_config"         : SimpleFileSpec("etc/origin/master/master-config.yaml"),
    "ose_node_config"           : SimpleFileSpec("etc/origin/node/node-config.yaml"),
    "ovirt_engine_confd"        : PatternSpec(r"etc/ovirt-engine/engine.conf.d/.*"),
    "ovirt_engine_server.log"   : SimpleFileSpec("var/log/ovirt-engine/server.log"),
    "ovs-vsctl_show"            : CommandSpec("/usr/bin/ovs-vsctl show"),
    "pacemaker.log"             : SimpleFileSpec("var/log/pacemaker.log"),
    "package_provides_java"     : CommandSpec("/bin/echo {java_command_package}", java_command_package=r"\S+"),
    'pam.conf'                  : SimpleFileSpec("etc/pam.conf"),
    "parted_-l"                 : CommandSpec("/sbin/parted -l -s"),
    "parted_-s-sos"             : First([PatternSpec(r"sos_commands/block/parted-s_.+"),
                                    PatternSpec(r"sos_commands/filesys/parted_-s_.+")]),
    "password-auth"             : SimpleFileSpec("etc/pam.d/password-auth"),
    'pcs_status'                : CommandSpec("/usr/sbin/pcs status"),
    "pluginconf.d"              : PatternSpec(r"etc/yum/pluginconf.d/\w+\.conf"),
    "postgresql.conf"           : First([SimpleFileSpec("var/lib/pgsql/data/postgresql.conf"),
                                    SimpleFileSpec("opt/rh/postgresql92/root/var/lib/pgsql/data/postgresql.conf"),
                                    SimpleFileSpec("database/postgresql.conf")]),
    "postgresql.log"            : First([PatternSpec(r"var/lib/pgsql/data/pg_log/postgresql-.+\.log", large_content=True),
                                    PatternSpec(r"opt/rh/postgresql92/root/var/lib/pgsql/data/pg_log/postgresql-.+\.log", large_content=True),
                                    PatternSpec(r"database/postgresql-.+\.log", large_content=True)]),
    "prelink_orig_md5"          : NoneGroup([CommandSpec("/usr/sbin/prelink -y --md5 {md5chk_files}", md5chk_files=r"\S+"),
                                    CommandSpec("/usr/bin/md5sum {md5chk_files}", md5chk_files=r"\S+")]),
    "proxy_server.conf"         : SimpleFileSpec("etc/swift/proxy-server.conf"),
    "ps_aux"                    : CommandSpec("/bin/ps aux"),
    "ps_auxcww"                 : CommandSpec("/bin/ps auxcww"),
    "ps_auxwww"                 : SimpleFileSpec("sos_commands/process/ps_auxwww"),
    "ps_axcwwo"                 : CommandSpec("/bin/ps axcwwo ucomm,%cpu,lstart"),
    "puppet_ssl_cert_ca_pem"    : NoneGroup([SimpleFileSpec("var/lib/puppet/ssl/certs/ca.pem"),
                                    SimpleFileSpec("sos_commands/foreman/foreman-debug/var/lib/puppet/ssl/certs/ca.pem")]),
    "pvs"                       : NoneGroup([CommandSpec('/sbin/pvs -a -v -o +pv_mda_free,pv_mda_size,pv_mda_count,pv_mda_used_count,pe_count --config="global{locking_type=0}"')]),
    "pvs_noheadings"            : CommandSpec("/sbin/pvs --nameprefixes --noheadings --separator='|' -a -o pv_all,vg_name --config=\"global{locking_type=0}\""),
    "qpid_stat_q"               : First([CommandSpec("/usr/bin/qpid-stat -q --ssl-certificate=/etc/pki/katello/qpid_client_striped.crt -b amqps://localhost:5671"),
                                    SimpleFileSpec("qpid_stat_queues"),
                                    SimpleFileSpec("qpid-stat-q"),
                                    SimpleFileSpec("sos_commands/foreman/foreman-debug/qpid_stat_queues"),
                                    SimpleFileSpec("sos_commands/foreman/foreman-debug/qpid-stat-q")]),
    "qemu.conf"                  : SimpleFileSpec("etc/libvirt/qemu.conf"),
    "qpid_stat_u"               : First([CommandSpec("/usr/bin/qpid-stat -u --ssl-certificate=/etc/pki/katello/qpid_client_striped.crt -b amqps://localhost:5671"),
                                    SimpleFileSpec("qpid_stat_subscriptions"),
                                    SimpleFileSpec("qpid-stat-u"),
                                    SimpleFileSpec("sos_commands/foreman/foreman-debug/qpid_stat_subscriptions"),
                                    SimpleFileSpec("sos_commands/foreman/foreman-debug/qpid-stat-u")]),
    "rabbitmq_logs"             : PatternSpec(r'var/log/rabbitmq/rabbit@.*(?<!-sasl)\.log',large_content=True),
    "rabbitmq_policies"         : CommandSpec("/usr/sbin/rabbitmqctl list_policies"),
    "rabbitmq_queues"           : CommandSpec("/usr/sbin/rabbitmqctl list_queues name messages consumers auto_delete"),
    "rabbitmq_report"           : CommandSpec("/usr/sbin/rabbitmqctl report"),
    "rabbitmq_startup_err"      : SimpleFileSpec("var/log/rabbitmq/startup_err", large_content=True),
    "rabbitmq_startup_log"      : SimpleFileSpec("var/log/rabbitmq/startup_log", large_content=True),
    "rabbitmq_users"            : CommandSpec("/usr/sbin/rabbitmqctl list_users"),
    "rc.local"                  : SimpleFileSpec("etc/rc.d/rc.local"),
    "redhat-release"            : SimpleFileSpec("etc/redhat-release"),
    "resolv.conf"               : SimpleFileSpec("etc/resolv.conf"),
    "rhn-charsets"              : First([CommandSpec("/usr/bin/rhn-charsets"),
                                    SimpleFileSpec("database-character-sets")]),
    "rhn.conf"                  : First([SimpleFileSpec("etc/rhn/rhn.conf"),
                                    SimpleFileSpec("conf/rhn/rhn/rhn.conf")]),
    "rhn-entitlement-cert.xml"  : First([PatternSpec(r"etc/sysconfig/rhn/rhn-entitlement-cert\.xml.*"),
                                    PatternSpec(r"conf/rhn/sysconfig/rhn/rhn-entitlement-cert\.xml.*")]),
    "rhn_hibernate.conf"        : First([SimpleFileSpec("usr/share/rhn/config-defaults/rhn_hibernate.conf"),
                                    SimpleFileSpec("config-defaults/rhn_hibernate.conf")]),
    "rhn-schema-stats"          : First([CommandSpec("/usr/bin/rhn-schema-stats -"),
                                    SimpleFileSpec("database/schema-stats.log")]),
    "rhn-schema-version"        : First([CommandSpec("/usr/bin/rhn-schema-version"),
                                    SimpleFileSpec("database-schema-version")]),
    "rhn_server_satellite.log"  : SimpleFileSpec("var/log/rhn/rhn_server_satellite.log"),
    "rhn_server_xmlrpc.log"     : First([SimpleFileSpec("var/log/rhn/rhn_server_xmlrpc.log", large_content=True),
                                    SimpleFileSpec("rhn-logs/rhn/rhn_server_xmlrpc.log", large_content=True)]),
    "rhn_search_daemon.log"     : First([SimpleFileSpec("var/log/rhn/search/rhn_search_daemon.log", large_content=True),
                                    SimpleFileSpec("rhn-logs/rhn/search/rhn_search_daemon.log", large_content=True)]),
    "rhn_taskomatic_daemon.log" : First([SimpleFileSpec("var/log/rhn/rhn_taskomatic_daemon.log"),
                                    SimpleFileSpec("rhn-logs/rhn/rhn_taskomatic_daemon.log")]),
    "rhsm.conf"                 : SimpleFileSpec("etc/rhsm/rhsm.conf"),
    "rhsm.log"                  : SimpleFileSpec("var/log/rhsm/rhsm.log", large_content=True),
    "root_crontab"              : First([CommandSpec("/usr/bin/crontab -l -u root"),
                                    SimpleFileSpec("sos_commands/crontab")]),
    "route"                     : First([CommandSpec("/sbin/route -n"),
                                    SimpleFileSpec("route")]),
    "rpm_-V_packages"           : CommandSpec("/bin/rpm -V coreutils procps procps-ng shadow-utils passwd sudo"),
    "rsyslog.conf"              : SimpleFileSpec("etc/rsyslog.conf"),
    "samba"                     : SimpleFileSpec("etc/samba/smb.conf"),
    "satellite_version.rb"      : First([SimpleFileSpec("usr/share/foreman/lib/satellite/version.rb"),
                                    SimpleFileSpec("sos_commands/foreman/foreman-debug/satellite_version"),
                                    SimpleFileSpec("satellite_version")]),
    "scheduler"                 : CommandSpec("/bin/cat {getblockscheduler}"),
    "scsi"                      : SimpleFileSpec("proc/scsi/scsi"),
    "secure"                    : SimpleFileSpec("var/log/secure", large_content=True),
    "selinux-config"            : SimpleFileSpec("etc/selinux/config"),
    "sestatus"                  : CommandSpec("/usr/sbin/sestatus -b"),
    "smartctl"                  : First([CommandSpec("/sbin/smartctl -a {block}", block=r"\S+"),
                                    PatternSpec(r"sos_commands/ata/smartctl_-a_\.dev\..*")]),
    "smbstatus_p"               : CommandSpec("/usr/bin/smbstatus -p"),
    "smbstatus_S"               : CommandSpec("/usr/bin/smbstatus -S"),
    "spfile.ora"                : PatternSpec(r"{ORACLE_HOME}/dbs/spfile.*\.ora"),
    "softnet_stat"              : SimpleFileSpec("proc/net/softnet_stat"),
    "ss"                        : First([CommandSpec("/usr/sbin/ss -tulpn"),
                                    SimpleFileSpec("ss"),
                                    SimpleFileSpec("sos_commands/foreman/foreman-debug/ss")]),
    "ssh_config"                : SimpleFileSpec("etc/ssh/ssh_config"),
    "sshd_config"               : SimpleFileSpec("etc/ssh/sshd_config"),
    "sshd_config_perms"         : CommandSpec("/bin/ls -l /etc/ssh/sshd_config"),
    "sssd_config"               : SimpleFileSpec("etc/sssd/sssd.conf"),
    "sssd_logs"                 : PatternSpec(r"var/log/sssd/.*\.log$"),
    "sysconfig_chronyd"         : SimpleFileSpec("etc/sysconfig/chronyd"),
    "sysconfig_httpd"           : SimpleFileSpec("etc/sysconfig/httpd"),
    "sysconfig_irqbalance"      : SimpleFileSpec("etc/sysconfig/irqbalance"),
    "sysconfig_mongod"          : All([SimpleFileSpec("etc/sysconfig/mongod"),
                                    SimpleFileSpec("etc/opt/rh/rh-mongodb26/sysconfig/mongod")]),
    "sysconfig_kdump"           : SimpleFileSpec("etc/sysconfig/kdump"),
    "sysconfig_ntpd"            : SimpleFileSpec("etc/sysconfig/ntpd"),
    "sysconfig_virt_who"        : SimpleFileSpec("etc/sysconfig/virt-who"),
    "sysctl"                    : CommandSpec("/sbin/sysctl -a"),
    "sysctl.conf"               : SimpleFileSpec("etc/sysctl.conf"),
    "sysctl.conf_initramfs"     : CommandSpec("/bin/lsinitrd /boot/initramfs-{uname_r}kdump.img -f /etc/sysctl.conf /etc/sysctl.d/*.conf", uname_r=r"\S+"),
    "systemctl_cinder-volume"   : CommandSpec("/bin/systemctl show openstack-cinder-volume"),
    "systemctl_list-unit-files" : CommandSpec("/bin/systemctl list-unit-files"),
    "systemctl_list-units"      : CommandSpec("/bin/systemctl list-units"),
    "systemctl_mariadb"         : CommandSpec("/bin/systemctl show mariadb"),
    "systemd_docker"            : SimpleFileSpec("usr/lib/systemd/system/docker.service"),
    "systemd_openshift_node"    : SimpleFileSpec("usr/lib/systemd/system/atomic-openshift-node.service"),
    "systemd_system.conf"       : SimpleFileSpec("etc/systemd/system.conf"),
    "systemid"                  : First([SimpleFileSpec("etc/sysconfig/rhn/systemid"),
                                    SimpleFileSpec("conf/rhn/sysconfig/rhn/systemid")]),
    "teamdctl_state_dump"       : CommandSpec("/usr/bin/teamdctl {iface} state dump", iface=r"team\S+"),
    "tomcat_web.xml"            : First([PatternSpec(r"etc/tomcat.*/web\.xml"),
                                    PatternSpec(r"conf/tomcat/tomcat.*/web\.xml")]),
    "tomcat_virtual_dir_context": CommandSpec("/bin/grep -R --include '*.xml' 'VirtualDirContext' /usr/share/tomcat*"),
    "tuned-adm"                 : CommandSpec("/sbin/tuned-adm list"),
    "udev-persistent-net.rules" : SimpleFileSpec("etc/udev/rules.d/70-persistent-net.rules"),
    "uname"                     : First([CommandSpec("/bin/uname -a"),
                                    SimpleFileSpec("uname")]),
    "up2date"                   : SimpleFileSpec("etc/sysconfig/rhn/up2date"),
    "uptime"                    : CommandSpec("/usr/bin/uptime"),
    "usr_journald.conf.d"       : PatternSpec(r"usr/lib/systemd/journald.conf.d/.+\.conf"),  # note that etc_journald.conf.d also exists
    "vgdisplay"                 : First([CommandSpec("/sbin/vgdisplay -vv"),
                                    CommandSpec("/sbin/vgdisplay")]),
    "vdsm.conf"                 : SimpleFileSpec("etc/vdsm/vdsm.conf"),
    "vdsm_id"                   : SimpleFileSpec("etc/vdsm/vdsm.id"),
    "vdsm.log"                  : SimpleFileSpec("var/log/vdsm/vdsm.log"),
    "vgs"                       : NoneGroup([CommandSpec('/sbin/vgs -v -o +vg_mda_count,vg_mda_free,vg_mda_size,vg_mda_used_count,vg_tags --config="global{locking_type=0}"')]),
    "vgs_noheadings"            : CommandSpec("/sbin/vgs --nameprefixes --noheadings --separator='|' -a -o vg_all --config=\"global{locking_type=0}\""),
    "virt-what"                 : CommandSpec("/usr/sbin/virt-what"),
    "virt_who_conf"             : All([PatternSpec(r"etc/virt-who\.conf"),
                                    PatternSpec(r"etc/virt-who.d/.*\.conf")]),
    "vsftpd"                    : SimpleFileSpec("etc/pam.d/vsftpd"),
    "vsftpd.conf"               : SimpleFileSpec("etc/vsftpd/vsftpd.conf"),
    "woopsie"                   : CommandSpec(r"/usr/bin/find /var/crash /var/tmp -path '*.reports-*/whoopsie-report'"),
    "xfs_info"                  : First([CommandSpec("/usr/sbin/xfs_info {mount}", mount=r'(?:/[\w-]*)+'),
                                    PatternSpec(r"sos_commands/xfs/xfs_info(_(?:\.[\w-]*)+)?")]),
    "xinetd.conf"               : SimpleFileSpec("etc/xinetd.conf"),
    "xinetd.d"                  : PatternSpec(r"etc/xinetd.d/.*"),
    "yum.conf"                  : SimpleFileSpec("etc/yum.conf"),
    "yum.log"                   : SimpleFileSpec("var/log/yum.log"),
    "yum-repolist"              : CommandSpec("/usr/bin/yum -C repolist"),
    "yum.repos.d"               : PatternSpec(r"etc/yum.repos.d/.*\.repo")
}
"""dict: Specifications for Insights data collection and parsers."""

pre_commands = {
    "block"                     : "/bin/ls /sys/block | awk '!/^ram|^\\.+$/ {print \"/dev/\" $1 \" unit s print\"}'",
    "ceph_osd_ec_profile_ls "   : "/usr/bin/ceph osd erasure-code-profile ls",
    "ceph_socket_files"         : "/bin/ls /var/run/ceph/ceph-*.*.asok",
    "docker_containers"         : "/usr/bin/docker ps -aq",
    "docker_images"             : "/usr/bin/docker images -q",
    "dumpdev"                   : "/bin/awk '/ext[234]/ { print $1; }' /proc/mounts",
    "getblockschedulers"        : "for device in $(ls /sys/block); do echo /sys/block/$device/queue/scheduler; done",
    "httpd_pid"                 : "/bin/ps aux | grep /usr/sbin/httpd | grep -v grep | head -1 | awk '{print $2}'",
    "iface"                     : "/sbin/ip -o link | awk -F ': ' '/.*link\\/ether/ {print $2}'",
    "md5chk_files"              : "/bin/ls -H /usr/lib*/{libfreeblpriv3.so,libsoftokn3.so} /etc/pki/product*/69.pem /etc/fonts/fonts.conf /dev/null 2>/dev/null",
    "module"                    : "/bin/ls /sys/module",
    "java_command_package"      : "for jp in `/bin/ps auxwww | grep java | grep -v grep| awk '{print $11}' | sort -u`; do echo $jp $(readlink -e `which $jp` | xargs rpm -qf); done",
    "uname_r"                   : "/bin/uname -r",
    "semid"                     : "/usr/bin/ipcs -s | awk '{if (NF == 5 && $2 ~ /^[0-9]+$/) print $2}'"
}
"""dict: Pre-commands used to generate data for specifications."""

meta_files = {
    "branch_info"               : SimpleFileSpec("branch_info"),
    "machine-id"                : SimpleFileSpec("etc/redhat-access-insights/machine-id"),
    "metadata.json"             : SimpleFileSpec("metadata.json"),
    "prev_uploader_log"         : SimpleFileSpec("var/log/redhat-access-insights/redhat-access-insights.log.1"),
    "uploader_log"              : SimpleFileSpec("var/log/redhat-access-insights/redhat-access-insights.log"),
}
"""dict: Metadata files added to the Insights archive by the client."""

openshift = {
    "oc_get_pod"                : CommandSpec("/usr/bin/oc get pod -o yaml --all-namespaces"),
    "oc_get_dc"                 : CommandSpec("/usr/bin/oc get dc -o yaml --all-namespaces"),
    "oc_get_service"            : CommandSpec("/usr/bin/oc get service -o yaml --all-namespaces"),
    "oc_get_rolebinding"        : CommandSpec("/usr/bin/oc get rolebinding -o yaml --all-namespaces"),
    "oc_get_project"            : CommandSpec("/usr/bin/oc get project -o yaml --all-namespaces"),
    "oc_get_role"               : CommandSpec("/usr/bin/oc get role -o yaml --all-namespaces"),
    "oc_get_pv"                 : CommandSpec("/usr/bin/oc get pv -o yaml --all-namespaces"),
    "oc_get_pvc"                : CommandSpec("/usr/bin/oc get pvc -o yaml --all-namespaces"),
    "oc_get_endpoints"          : CommandSpec("/usr/bin/oc get endpoints -o yaml --all-namespaces")
}
"""dict: Openshift specific data collection specifications."""

# flake8: noqa
