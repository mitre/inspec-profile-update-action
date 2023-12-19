control 'SV-40722' do
  title 'The SSH daemon must not allow rhosts RSA authentication.'
  desc 'If SSH permits rhosts RSA authentication, a user may be able to log in based on the keys of the host originating the request and not any user-specific authentication.'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file and remove the RhostsRSAAuthentication setting or change the value of the RhostsRSAAuthentication setting to "no".'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-22487'
  tag rid: 'SV-40722r1_rule'
  tag stig_id: 'GEN005538'
  tag gtitle: 'GEN005538'
  tag fix_id: 'F-34581r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
