control 'SV-234999' do
  title 'SUSE operating system file systems that are used with removable media must be mounted to prevent files with the setuid and setgid bit set from being executed.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify SUSE operating system file systems used for removable media are mounted with the "nosuid" option.

Check the file systems that are mounted at boot time with the following command:

> more /etc/fstab

UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid 0 0

If a file system found in "/etc/fstab" refers to removable media and it does not have the "nosuid" option set, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system "/etc/fstab" file to use the "nosuid" option on file systems that are associated with removable media.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38187r619266_chk'
  tag severity: 'medium'
  tag gid: 'V-234999'
  tag rid: 'SV-234999r622137_rule'
  tag stig_id: 'SLES-15-040150'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38150r619267_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
