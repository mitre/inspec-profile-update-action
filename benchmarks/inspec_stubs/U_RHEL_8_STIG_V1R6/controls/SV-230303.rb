control 'SV-230303' do
  title 'RHEL 8 must prevent special devices on file systems that are used with removable media.'
  desc 'The "nodev" mount option causes the system not to interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify file systems that are used for removable media are mounted with the "nodev" option with the following command:

$ sudo more /etc/fstab

UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222 /mnt/usbflash vfat noauto,owner,ro,nosuid,nodev,noexec 0 0

If a file system found in "/etc/fstab" refers to removable media and it does not have the "nodev" option set, this is a finding.'
  desc 'fix', 'Configure the "/etc/fstab" to use the "nodev" option on file systems that are associated with removable media.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32972r567655_chk'
  tag severity: 'medium'
  tag gid: 'V-230303'
  tag rid: 'SV-230303r627750_rule'
  tag stig_id: 'RHEL-08-010600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-32947r567656_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
