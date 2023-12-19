control 'SV-217901' do
  title 'The system boot loader configuration file(s) must be owned by root.'
  desc 'Only root should be able to modify important boot parameters.'
  desc 'check', 'To check the ownership of "/boot/grub/grub.conf", run the command: 

$ ls -lL /boot/grub/grub.conf

If properly configured, the output should indicate that the owner is "root".
If it does not, this is a finding.'
  desc 'fix', 'The file "/boot/grub/grub.conf" should be owned by the "root" user to prevent destruction or modification of the file. To properly set the owner of "/boot/grub/grub.conf", run the command: 

# chown root /boot/grub/grub.conf'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19382r376718_chk'
  tag severity: 'medium'
  tag gid: 'V-217901'
  tag rid: 'SV-217901r603264_rule'
  tag stig_id: 'RHEL-06-000065'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19380r376719_fix'
  tag 'documentable'
  tag legacy: ['V-38579', 'SV-50380']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
