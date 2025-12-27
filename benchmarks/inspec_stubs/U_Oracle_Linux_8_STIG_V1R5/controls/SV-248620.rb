control 'SV-248620' do
  title 'OL 8 file systems that contain user home directories must not execute binary files.'
  desc 'The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(Verify that file systems containing user home directories are mounted with the "noexec" option.
 
Find the file system(s) that contain the user home directories with the following command: 
 
$ sudo awk -F: '($3>=1000)&&($1!="nobody"){print $1,$3,$6}' /etc/passwd 
 
smithj 1001 /home/smithj 
robinst 1002 /home/robinst 
 
Check the file systems that are mounted at boot time with the following command: 
 
$ sudo more /etc/fstab 
 
UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home ext4 rw,relatime,discard,data=ordered,nosuid,nodev,noexec 0 2 
 
If a file system found in "/etc/fstab" refers to the user home directory file system and it does not have the "noexec" option set, this is a finding.)
  desc 'fix', 'Configure the "/etc/fstab" to use the "noexec" option on file systems that contain user home directories for interactive users.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52054r779424_chk'
  tag severity: 'medium'
  tag gid: 'V-248620'
  tag rid: 'SV-248620r779426_rule'
  tag stig_id: 'OL08-00-010590'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52008r779425_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
