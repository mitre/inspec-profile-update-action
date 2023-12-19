control 'SV-220089' do
  title 'Removable media, remote file systems, and any file system that does not contain approved setuid files must be mounted with the "nosuid" option.'
  desc 'The "nosuid" mount option causes the system to not execute setuid files with owner privileges.  This option must be used for mounting any file system that does not contain approved setuid files.  Executing setuid files from untrusted file systems, or file systems that do not contain approved setuid files, increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Check /etc/vfstab and verify the "nosuid" mount option is used on any user filesystem (such as /export/home) or filesystems mounted from removable media or network shares.
# cat /etc/vfstab

Check zfs filesystems for setuid mounts.
#zfs get setuid'
  desc 'fix', 'Use the following procedure for UFS filesystems.
Edit /etc/vfstab and add the "nosuid" mount option to any user filesystem (such as /export/home) or filesystems mounted from removable media or network shares. 

Use the following procedure for ZFS filesystems.
# zfs setuid = off < file system >'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36428r602887_chk'
  tag severity: 'medium'
  tag gid: 'V-220089'
  tag rid: 'SV-220089r854459_rule'
  tag stig_id: 'GEN002420'
  tag gtitle: 'SRG-OS-000368'
  tag fix_id: 'F-36392r602888_fix'
  tag 'documentable'
  tag legacy: ['V-805', 'SV-39813']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
