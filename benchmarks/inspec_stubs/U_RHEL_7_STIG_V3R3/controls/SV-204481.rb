control 'SV-204481' do
  title 'The Red Hat Enterprise Linux operating system must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify file systems that are used for removable media are mounted with the "nosuid" option.

Check the file systems that are mounted at boot time with the following command:

# more /etc/fstab

UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid 0 0

If a file system found in "/etc/fstab" refers to removable media and it does not have the "nosuid" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option on file systems that are associated with removable media.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4605r88635_chk'
  tag severity: 'medium'
  tag gid: 'V-204481'
  tag rid: 'SV-204481r603261_rule'
  tag stig_id: 'RHEL-07-021010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-4605r88636_fix'
  tag 'documentable'
  tag legacy: ['SV-86667', 'V-72043']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
