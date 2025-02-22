control 'SV-35060' do
  title 'The SSH public host key files must have mode 0644 or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  desc 'check', 'Check the permissions for the SSH public host key files.
# ls -lL /opt/ssh/etc/ssh_host_dsa_key.pub
# ls -lL /opt/ssh/etc/ssh_host_rsa_key.pub

If any file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the permissions for the SSH public host key files.
# chmod 0644 /opt/ssh/etc/*key.pub'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-34928r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22471'
  tag rid: 'SV-35060r1_rule'
  tag stig_id: 'GEN005522'
  tag gtitle: 'GEN005522'
  tag fix_id: 'F-30234r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
