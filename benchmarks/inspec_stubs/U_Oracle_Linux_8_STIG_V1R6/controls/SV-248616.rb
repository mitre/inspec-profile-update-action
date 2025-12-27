control 'SV-248616' do
  title 'OL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that contain user home directories.'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(Verify that file systems containing user home directories are mounted with the "nosuid" option.
 
Find the file system(s) that contain the user home directories with the following command: 
 
$ sudo awk -F: '($3>=1000)&&($1!="nobody"){print $1,$3,$6}' /etc/passwd 
 
smithj 1001 /home/smithj 
robinst 1002 /home/robinst 
 
Check the file systems that are mounted at boot time with the following command: 
 
$ sudo more /etc/fstab 
 
UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home ext4 rw,relatime,discard,data=ordered,nosuid,nodev,noexec 0 2 
 
If a file system found in "/etc/fstab" refers to the user home directory file system and it does not have the "nosuid" option set, this is a finding.)
  desc 'fix', 'Configure "/etc/fstab" to use the "nosuid" option on file systems that contain user home directories for interactive users.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52050r779412_chk'
  tag severity: 'medium'
  tag gid: 'V-248616'
  tag rid: 'SV-248616r779414_rule'
  tag stig_id: 'OL08-00-010570'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52004r779413_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
