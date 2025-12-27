control 'SV-217903' do
  title 'The system boot loader configuration file(s) must have mode 0600 or less permissive.'
  desc 'Proper permissions ensure that only the root user can modify important boot parameters.'
  desc 'check', 'To check the permissions of "/boot/grub/grub.conf", run the command:

$ sudo ls -lL /boot/grub/grub.conf

If properly configured, the output should indicate the following permissions: "-rw-------"

If it does not, this is a finding.'
  desc 'fix', 'Set file permissions for "/boot/grub/grub.conf" to 600, which is the default.

To properly set the permissions of "/boot/grub/grub.conf", run the command:

$ chmod 600 /boot/grub/grub.conf'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19384r376724_chk'
  tag severity: 'medium'
  tag gid: 'V-217903'
  tag rid: 'SV-217903r603264_rule'
  tag stig_id: 'RHEL-06-000067'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19382r376725_fix'
  tag 'documentable'
  tag legacy: ['V-38583', 'SV-50384']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
