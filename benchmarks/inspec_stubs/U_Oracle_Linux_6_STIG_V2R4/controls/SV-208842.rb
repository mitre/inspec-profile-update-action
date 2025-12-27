control 'SV-208842' do
  title 'The system boot loader configuration file(s) must have mode 0600 or less permissive.'
  desc 'Proper permissions ensure that only the root user can modify important boot parameters.'
  desc 'check', 'To check the permissions of "/boot/grub/grub.conf", run the command:

$ sudo ls -lL /boot/grub/grub.conf 

If properly configured, the output should indicate the following permissions: "-rw-------"
If it does not, this is a finding.'
  desc 'fix', 'File permissions for "/boot/grub/grub.conf" should be set to 600, which is the default. To properly set the permissions of "/boot/grub/grub.conf", run the command:

# chmod 600 /boot/grub/grub.conf

Boot partitions based on VFAT, NTFS, or other non-standard configurations may require alternative measures.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9095r357506_chk'
  tag severity: 'medium'
  tag gid: 'V-208842'
  tag rid: 'SV-208842r603263_rule'
  tag stig_id: 'OL6-00-000067'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9095r357507_fix'
  tag 'documentable'
  tag legacy: ['SV-65149', 'V-50943']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
