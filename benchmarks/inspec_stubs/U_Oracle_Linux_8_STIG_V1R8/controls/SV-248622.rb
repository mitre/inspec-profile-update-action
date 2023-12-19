control 'SV-248622' do
  title 'OL 8 file systems must not execute binary files on removable media.'
  desc 'The "noexec" mount option causes the system not to execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify that file systems used for removable media are mounted with the "noexec" option with the following command: 
 
$ sudo more /etc/fstab 
 
UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid,nodev,noexec 0 0 
 
If a file system found in "/etc/fstab" refers to removable media and it does not have the "noexec" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "noexec" option on file systems that are associated with removable media.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52056r779430_chk'
  tag severity: 'medium'
  tag gid: 'V-248622'
  tag rid: 'SV-248622r779432_rule'
  tag stig_id: 'OL08-00-010610'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52010r779431_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
