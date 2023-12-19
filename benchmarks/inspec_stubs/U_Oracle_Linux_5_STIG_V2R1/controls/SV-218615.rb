control 'SV-218615' do
  title 'The SSH daemon must not allow rhosts RSA authentication.'
  desc 'If SSH permits rhosts RSA authentication, a user may be able to log in based on the keys of the host originating the request and not any user-specific authentication.'
  desc 'check', %q(Check the SSH daemon configuration for the RhostsRSAAuthentication setting.

# grep -i RhostsRSAAuthentication /etc/ssh/sshd_config | grep -v '^#'
 
If the setting is set to "yes", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the "RhostsRSAAuthentication" setting value to "no".

Restart the SSH daemon.
# /sbin/service sshd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20090r556043_chk'
  tag severity: 'medium'
  tag gid: 'V-218615'
  tag rid: 'SV-218615r603259_rule'
  tag stig_id: 'GEN005538'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20088r556044_fix'
  tag 'documentable'
  tag legacy: ['V-22487', 'SV-64081']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
