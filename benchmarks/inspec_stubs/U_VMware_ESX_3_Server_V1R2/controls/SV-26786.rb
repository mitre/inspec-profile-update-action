control 'SV-26786' do
  title 'The SSH daemon must not allow rhosts RSA authentication.'
  desc 'If SSH permits rhosts RSA authentication, a user may be able to log in based on the keys of the host originating the request and not any user-specific authentication.'
  desc 'check', "Check the SSH daemon configuration for the RhostsRSAAuthentication  setting.
# grep -i RhostsRSAAuthentication /etc/ssh/sshd_config | grep -v '^#' 
If the setting is not present or not set to no, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the RhostsRSAAuthentication setting value to no.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27789r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22487'
  tag rid: 'SV-26786r1_rule'
  tag stig_id: 'GEN005538'
  tag gtitle: 'GEN005538'
  tag fix_id: 'F-24035r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
