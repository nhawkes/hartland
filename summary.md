### host
Linux 7.0.0-1017-azure x86_64
2
               total        used        free      shared  buff/cache   available
Mem:               7           0           6           0           0           6
/dev/root        72G   59G   14G  82% /
PRETTY_NAME="Ubuntu 24.04.5 LTS"
uid=1001(runner) gid=1001(runner) groups=1001(runner),4(adm),100(users),118(docker),999(systemd-journal)
exit=0

### sysctl userns
kernel.apparmor_restrict_unprivileged_userns = 1
kernel.unprivileged_userns_clone = 1
user.max_user_namespaces = 28076
exit=0

### runner has sudo
exit=0

### unprivileged unshare as runner
unshare: write failed /proc/self/uid_map: Operation not permitted
exit=1

### token visible to runner uid (expected: yes)
readable: /proc/1882/environ
readable: /proc/1883/environ
readable: /proc/1943/environ
scan-done
exit=0

### token visible to sandbox uid (want: none)
scan-done
exit=0

### sandbox uid has sudo (want: fail)
sudo: a password is required
exit=1

### sandbox uid unprivileged unshare
unshare: write failed /proc/self/uid_map: Operation not permitted
exit=1

### network inside netns (want: fail)
unshare: write failed /proc/self/uid_map: Operation not permitted
exit=1

### network for sandbox uid without netns (info)
connected
exit=0

### credential files readable by sandbox (want: none)
/opt/az/lib/python3.14/site-packages/certifi/cacert.pem
/etc/pki/fwupd/LVFS-CA-2025PQ.pem
/etc/pki/fwupd/LVFS-CA.pem
/etc/pki/fwupd-metadata/LVFS-CA-2025PQ.pem
/etc/pki/fwupd-metadata/LVFS-CA.pem
/etc/ssl/certs/OISTE_WISeKey_Global_Root_GB_CA.pem
/etc/ssl/certs/OISTE_WISeKey_Global_Root_GC_CA.pem
/etc/ssl/certs/GTS_Root_R4.pem
/etc/ssl/certs/QuoVadis_Root_CA_3_G3.pem
/etc/ssl/certs/GlobalSign_Root_R46.pem
/etc/ssl/certs/Hellenic_Academic_and_Research_Institutions_ECC_RootCA_2015.pem
/etc/ssl/certs/GlobalSign_Root_CA_-_R3.pem
/etc/ssl/certs/Certum_EC-384_CA.pem
/etc/ssl/certs/DigiCert_Global_Root_G3.pem
/etc/ssl/certs/ISRG_Root_X1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Microsoft_ECC_Root_Certificate_Authority_2017.pem
/etc/ssl/certs/HARICA_TLS_RSA_Root_CA_2021.pem
/etc/ssl/certs/OISTE_Server_Root_ECC_G1.pem
/etc/ssl/certs/GTS_Root_R3.pem
find-done
exit=0

### runner home readable by sandbox (info)
ls: cannot access '/home/runner/work': Permission denied
drwxr-x--- 13 runner runner 4096 Nov  8 12:53 /home/runner
ls: cannot open directory '/home/runner': Permission denied
exit=0

### bwrap as sandbox uid
bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted
exit=1

### jail: identity and capabilities
uid=1002(hlsandbox) gid=1002(hlsandbox) groups=1002(hlsandbox)
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000000000000000
CapAmb:	0000000000000000
NoNewPrivs:	1
exit=0

### jail: network (want: fail)
bash: connect: Network is unreachable
bash: line 1: /dev/tcp/1.1.1.1/443: Network is unreachable
no-network
exit=0

### jail: visible processes (want: only own)
1 2 3 4 
exit=0

### jail: token scan (want: none)
scan-done
exit=0

### jail: sudo (want: fail)
sudo: The "no new privileges" flag is set, which prevents sudo from running as root.
sudo: If sudo is running in a container, you may need to adjust the container configuration to disable the flag.
exit=1

### jail: runner home (want: denied)
ls: cannot open directory '/home/runner': Permission denied
exit=2

### jail: launch overhead, 100 runs
8ms per 100 / 100 = ms each x0.01 -> see raw
total_ns=810877754
exit=0

### bwrap after sysctl, as sandbox uid
uid=1002 gid=1002 groups=1002
/usr/bin/sh: 1: cannot create /dev/tcp/1.1.1.1/443: Directory nonexistent
exit=2

