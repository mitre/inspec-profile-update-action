control 'SV-208840' do
  title 'The system boot loader configuration file(s) must be owned by root.'
  desc 'Only root should be able to modify important boot parameters.'
  desc 'check', 'To check the ownership of "/boot/grub/grub.conf", run the command: 

$ ls -lL /boot/grub/grub.conf

If properly configured, the output should indicate that the owner is "root".
If it does not, this is a finding.'
  desc 'fix', 'The file "/boot/grub/grub.conf" should be owned by the "root" user to prevent destruction or modification of the file. To properly set the owner of "/boot/grub/grub.conf", run the command: 

# chown root /boot/grub/grub.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9093r357500_chk'
  tag severity: 'medium'
  tag gid: 'V-208840'
  tag rid: 'SV-208840r603263_rule'
  tag stig_id: 'OL6-00-000065'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9093r357501_fix'
  tag 'documentable'
  tag legacy: ['SV-65139', 'V-50933']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
