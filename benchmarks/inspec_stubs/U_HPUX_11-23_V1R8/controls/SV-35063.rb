control 'SV-35063' do
  title 'The SSH private host key files must have mode 0600 or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  desc 'check', 'Check the permissions for SSH private host key files.
ls -lL /opt/ssh/etc/ssh_host_dsa_key 
ls -lL /opt/ssh/etc/ssh_host_rsa_key

If any file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the permissions for the SSH private host key files.
# chmod 0600 /opt/ssh/etc/*key'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-34930r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22472'
  tag rid: 'SV-35063r1_rule'
  tag stig_id: 'GEN005523'
  tag gtitle: 'GEN005523'
  tag fix_id: 'F-30236r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
