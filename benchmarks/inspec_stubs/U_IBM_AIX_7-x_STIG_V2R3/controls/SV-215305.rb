control 'SV-215305' do
  title 'The AIX SSH daemon must not allow RhostsRSAAuthentication.'
  desc 'If SSH permits rhosts RSA authentication, a user may be able to log in based on the keys of the host originating the request and not any user-specific authentication.'
  desc 'check', %q(Check the SSH daemon configuration for the "RhostsRSAAuthentication" setting by running: 
# grep -i RhostsRSAAuthentication /etc/ssh/sshd_config | grep -v '^#' 

The above command should yield the following output:
RhostsRSAAuthentication no

If the setting is present and set to "yes", this is a finding.)
  desc 'fix', 'Edit the "/etc/ssh/sshd_config file", add the following line, and save the change:
RhostsRSAAuthentication no

Restart the SSH daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16503r294366_chk'
  tag severity: 'medium'
  tag gid: 'V-215305'
  tag rid: 'SV-215305r508663_rule'
  tag stig_id: 'AIX7-00-002123'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-16501r294367_fix'
  tag 'documentable'
  tag legacy: ['V-91749', 'SV-101847']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
