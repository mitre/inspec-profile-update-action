control 'SV-230523' do
  title 'The RHEL 8 fapolicy module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.'
  desc 'The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

Utilizing a whitelist provides a configuration management method for allowing the execution of only authorized software. Using only authorized software decreases risk by limiting the number of potential vulnerabilities. Verification of whitelisted software occurs prior to execution or at system startup.

User home directories/folders may contain information of a sensitive nature. Non-privileged users should coordinate any sharing of information with an SA through shared resources.

RHEL 8 ships with many optional packages. One such package is a file access policy daemon called "fapolicyd". "fapolicyd" is a userspace daemon that determines access rights to files based on attributes of the process and file. It can be used to either blacklist or whitelist processes or file access.

Proceed with caution with enforcing the use of this daemon. Improper configuration may render the system non-functional.

'
  desc 'check', 'Verify the RHEL 8 "fapolicyd" is enabled and employs a deny-all, permit-by-exception policy.

Check that "fapolicyd" is installed, running, and in enforcing mode with the following commands:

$ sudo yum list installed fapolicyd

Installed Packages
fapolicyd.x86_64

$ sudo systemctl status fapolicyd.service

fapolicyd.service - File Access Policy Daemon
Loaded: loaded (/usr/lib/systemd/system/fapolicyd.service; enabled; vendor preset: disabled)
Active: active (running)

$ sudo grep permissive /etc/fapolicyd/fapolicyd.conf

permissive = 0

Check that fapolicyd employs a deny-all policy on system mounts with the following commands:

$ sudo tail /etc/fapolicyd/fapolicyd.rules

allow exe=/usr/bin/python3.4 dir=execdirs ftype=text/x-pyton
deny_audit pattern ld_so all
deny all all

$ sudo cat /etc/fapolicyd/fapolicyd.mounts

/dev/shm
/run
/sys/fs/cgroup
/
/home
/boot
/run/user/42
/run/user/1000

If fapolicyd is not running in enforcement mode on all system mounts with a deny-all, permit-by-exception policy, this is a finding.'
  desc 'fix', %q(Configure RHEL 8 to employ a deny-all, permit-by-exception application whitelisting policy with "fapolicyd" using the following commands:

Install and enable "fapolicyd":

$ sudo yum install fapolicyd.x86_64

$ sudo mount | egrep '^tmpfs| ext4| ext3| xfs' | awk '{ printf "%s\n", $3 }' >> /etc/fapolicyd/fapolicyd.mounts

$ sudo systemctl enable --now fapolicyd

With the "fapolicyd" installed and enabled, configure the daemon to function in permissive mode until the whitelist is built correctly to avoid system lockout. Do this by editing the "/etc/fapolicyd/fapolicyd.conf" file with the following line:

permissive = 1

Build the whitelist in the "/etc/fapolicyd/fapolicyd.rules" file ensuring the last rule is "deny all all".

Once it is determined the whitelist is built correctly, set the fapolicyd to enforcing mode by editing the "permissive" line in the /etc/fapolicyd/fapolicyd.conf file.

permissive = 0)
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33192r568315_chk'
  tag severity: 'medium'
  tag gid: 'V-230523'
  tag rid: 'SV-230523r627750_rule'
  tag stig_id: 'RHEL-08-040135'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-33167r568316_fix'
  tag satisfies: ['SRG-OS-000368-GPOS-00154', 'SRG-OS-000370-GPOS-00155', 'SRG-OS-000480-GPOS-00232']
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
