control 'SV-221742' do
  title 'The Oracle Linux operating system must prevent files with the setuid and setgid bit set from being executed on file systems that are used with removable media.'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify file systems used for removable media are mounted with the "nosuid" option.

Check the file systems mounted at boot time with the following command:

# more /etc/fstab

UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid 0 0

If a file system found in "/etc/fstab" refers to removable media and it does not have the "nosuid" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option on file systems that are associated with removable media.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23457r419298_chk'
  tag severity: 'medium'
  tag gid: 'V-221742'
  tag rid: 'SV-221742r603260_rule'
  tag stig_id: 'OL07-00-021010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23446r419299_fix'
  tag 'documentable'
  tag legacy: ['SV-108327', 'V-99223']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
