control 'SV-37863' do
  title 'The SSH private host key files must have mode 0600 or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  desc 'fix', 'Change the permissions for the SSH private host key files.
# chmod 0600 /etc/ssh/*key'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22472'
  tag rid: 'SV-37863r1_rule'
  tag stig_id: 'GEN005523'
  tag gtitle: 'GEN005523'
  tag fix_id: 'F-32347r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
