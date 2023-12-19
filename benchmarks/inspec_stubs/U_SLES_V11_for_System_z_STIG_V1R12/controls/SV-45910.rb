control 'SV-45910' do
  title 'NIS maps must be protected through hard-to-guess domain names.'
  desc 'The use of hard-to-guess NIS domain names provides additional protection from unauthorized access to the NIS directory information.'
  desc 'check', 'Check the domain name for NIS maps.

Procedure:
# domainname

If the name returned is simple to guess, such as the organization name, building or room name, etc., this is a finding.'
  desc 'fix', 'Change the NIS domainname to a value difficult to guess. Consult vendor documentation for the required procedure.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43218r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12026'
  tag rid: 'SV-45910r1_rule'
  tag stig_id: 'GEN006420'
  tag gtitle: 'GEN006420'
  tag fix_id: 'F-39289r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
