control 'SV-218607' do
  title 'The SSH public host key files must have mode 0644 or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  desc 'check', 'Check the permissions for SSH public host key files.

# ls -lL /etc/ssh/*key.pub

If any file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the permissions for the SSH public host key files.

# chmod 0644 /etc/ssh/*key.pub'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20082r556019_chk'
  tag severity: 'medium'
  tag gid: 'V-218607'
  tag rid: 'SV-218607r603259_rule'
  tag stig_id: 'GEN005522'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20080r556020_fix'
  tag 'documentable'
  tag legacy: ['V-22471', 'SV-63841']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
