control 'SV-227043' do
  title 'NIS maps must be protected through hard-to-guess domain names.'
  desc 'The use of hard-to-guess NIS domain names provides additional protection from unauthorized access to the NIS directory information.'
  desc 'check', 'Check the domain name for NIS maps.

Procedure:
# domainname

If the name returned is simple to guess, such as the organization name, building, or room name, etc., this is a finding.'
  desc 'fix', 'Change the NIS domain name to a value difficult to guess.  Consult vendor documentation for the required procedure.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29205r485483_chk'
  tag severity: 'medium'
  tag gid: 'V-227043'
  tag rid: 'SV-227043r603265_rule'
  tag stig_id: 'GEN006420'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29193r485484_fix'
  tag 'documentable'
  tag legacy: ['SV-12527', 'V-12026']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
