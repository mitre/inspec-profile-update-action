control 'SV-227900' do
  title 'The SSH public host key files must have mode 0644 or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  desc 'check', 'Check the permissions for SSH public host key files.
# ls -lL /etc/ssh/*key.pub
If any file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the permissions for the SSH public host key files.
# chmod 0644 /etc/ssh/*key.pub'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30062r490105_chk'
  tag severity: 'medium'
  tag gid: 'V-227900'
  tag rid: 'SV-227900r603266_rule'
  tag stig_id: 'GEN005522'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30050r490106_fix'
  tag 'documentable'
  tag legacy: ['V-22471', 'SV-26764']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
