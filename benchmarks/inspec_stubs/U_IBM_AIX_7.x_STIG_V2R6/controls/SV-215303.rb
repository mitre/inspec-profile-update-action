control 'SV-215303' do
  title 'The AIX SSH daemon must be configured to disable user .rhosts files.'
  desc 'Trust .rhost file means a compromise on one host can allow an attacker to move trivially to other hosts.'
  desc 'check', %q(Check the SSH daemon configuration for allowed ".rhosts" using command: 

# grep -i IgnoreRhosts /etc/ssh/sshd_config | grep -v '^#' 
IgnoreRhosts yes

If no lines are returned, or the returned "IgnoreRhosts" directive is not set to "yes", this is a finding.)
  desc 'fix', 'Edit "/etc/ssh/sshd_config" and add or update the "IgnoreRhosts " line as:
IgnoreRhosts  yes

Save the change and restart ssh daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16501r294360_chk'
  tag severity: 'medium'
  tag gid: 'V-215303'
  tag rid: 'SV-215303r508663_rule'
  tag stig_id: 'AIX7-00-002121'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-16499r294361_fix'
  tag 'documentable'
  tag legacy: ['SV-101843', 'V-91745']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
