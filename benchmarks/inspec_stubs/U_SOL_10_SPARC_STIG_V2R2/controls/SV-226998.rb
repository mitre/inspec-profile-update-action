control 'SV-226998' do
  title 'The SSH daemon must not allow rhosts RSA authentication.'
  desc 'If SSH permits rhosts RSA authentication, a user may be able to log in based on the keys of the host originating the request and not any user-specific authentication.'
  desc 'check', "Check the SSH daemon configuration for the RhostsRSAAuthentication setting.
# grep -i RhostsRSAAuthentication /etc/ssh/sshd_config | grep -v '^#'
If the setting is set to yes, this is a finding."
  desc 'fix', 'Edit the SSH daemon configuration and change the RhostsRSAAuthentication setting value to no or remove it entirely.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29160r485333_chk'
  tag severity: 'medium'
  tag gid: 'V-226998'
  tag rid: 'SV-226998r603265_rule'
  tag stig_id: 'GEN005538'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29148r485334_fix'
  tag 'documentable'
  tag legacy: ['V-22487', 'SV-40396']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
