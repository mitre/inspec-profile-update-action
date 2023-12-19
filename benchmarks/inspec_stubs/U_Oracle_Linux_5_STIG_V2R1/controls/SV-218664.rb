control 'SV-218664' do
  title 'NIS maps must be protected through hard-to-guess domain names.'
  desc 'The use of hard-to-guess NIS domain names provides additional protection from unauthorized access to the NIS directory information.'
  desc 'check', 'Check the domain name for NIS maps.

Procedure:
# domainname

If the name returned is simple to guess, such as the organization name, building or room name, etc., this is a finding.

If the system does not use NIS, this is not applicable.'
  desc 'fix', 'Change the NIS domainname to a value difficult to guess. Consult vendor documentation for the required procedure.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20139r556406_chk'
  tag severity: 'medium'
  tag gid: 'V-218664'
  tag rid: 'SV-218664r603259_rule'
  tag stig_id: 'GEN006420'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20137r556407_fix'
  tag 'documentable'
  tag legacy: ['V-12026', 'SV-63785']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
