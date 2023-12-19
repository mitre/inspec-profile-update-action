control 'SV-215418' do
  title 'NIS maps must be protected through hard-to-guess domain names on AIX.'
  desc 'The use of hard-to-guess NIS domain names provides additional protection from unauthorized access to the NIS directory information.'
  desc 'check', 'Check the domain name for NIS maps using command:

# domainname 

If no ouput is returned or the name returned is simple to guess, such as the organization name, building, or room name, etc., this is a finding.'
  desc 'fix', 'Change the NIS domain name to a value difficult to guess. Consult vendor documentation for the required procedure.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16616r294705_chk'
  tag severity: 'medium'
  tag gid: 'V-215418'
  tag rid: 'SV-215418r508663_rule'
  tag stig_id: 'AIX7-00-003123'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16614r294706_fix'
  tag 'documentable'
  tag legacy: ['V-91683', 'SV-101781']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
