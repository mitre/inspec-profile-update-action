control 'SV-220036' do
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
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36364r602695_chk'
  tag severity: 'medium'
  tag gid: 'V-220036'
  tag rid: 'SV-220036r854394_rule'
  tag stig_id: 'GEN002420'
  tag gtitle: 'SRG-OS-000368'
  tag fix_id: 'F-36328r602696_fix'
  tag 'documentable'
  tag legacy: ['SV-39813', 'V-805']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
