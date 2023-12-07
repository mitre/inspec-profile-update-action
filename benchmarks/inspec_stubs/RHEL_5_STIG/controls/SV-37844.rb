control 'SV-37844' do
  title 'The SSH public host key files must have mode 0644 or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  desc 'fix', 'Change the permissions for the SSH public host key files.
# chmod 0644 /etc/ssh/*key.pub'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22471'
  tag rid: 'SV-37844r1_rule'
  tag stig_id: 'GEN005522'
  tag gtitle: 'GEN005522'
  tag fix_id: 'F-32310r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
