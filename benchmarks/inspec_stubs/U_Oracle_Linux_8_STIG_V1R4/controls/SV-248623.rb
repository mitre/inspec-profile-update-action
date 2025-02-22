control 'SV-248623' do
  title 'OL 8 must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media.'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify that file systems used for removable media are mounted with the "nosuid" option with the following command: 
 
$ sudo more /etc/fstab 
 
UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid,nodev,noexec 0 0 
 
If a file system found in "/etc/fstab" refers to removable media and it does not have the "nosuid" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option on file systems that are associated with removable media.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52057r779433_chk'
  tag severity: 'medium'
  tag gid: 'V-248623'
  tag rid: 'SV-248623r779435_rule'
  tag stig_id: 'OL08-00-010620'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52011r779434_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
