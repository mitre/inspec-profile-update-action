control 'SV-215306' do
  title 'If AIX SSH daemon is required, the SSH daemon must only listen on the approved listening IP addresses.'
  desc 'The SSH daemon should only listen on the approved listening IP addresses. Otherwise the SSH service could be subject to unauthorized access.'
  desc 'check', %q(From the command prompt, run the following command to check if "ListenAddress" is defined in SSH config file:

# grep -i ListenAddress /etc/ssh/sshd_config | grep -v '^#'
ListenAddress  10.17.76.74

If no configuration is returned, or if a returned listen configuration contains addresses not permitted, this is a finding.)
  desc 'fix', 'Edit the SSH daemon config file and add/modify the "ListenAddress" network addresses:
# vi /etc/ssh/sshd_config

Restart SSH daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16504r294369_chk'
  tag severity: 'medium'
  tag gid: 'V-215306'
  tag rid: 'SV-215306r508663_rule'
  tag stig_id: 'AIX7-00-002124'
  tag gtitle: 'SRG-OS-000480-GPOS-00232'
  tag fix_id: 'F-16502r294370_fix'
  tag 'documentable'
  tag legacy: ['V-91773', 'SV-101871']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
