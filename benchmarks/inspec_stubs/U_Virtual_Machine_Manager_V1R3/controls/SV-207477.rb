control 'SV-207477' do
  title 'The VMM must require users to re-authenticate when changing roles.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When VMMs provide the capability to change security roles, it is critical the user re-authenticate.'
  desc 'check', 'Verify the VMM requires users to re-authenticate when changing roles.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to require users to re-authenticate when changing roles.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7734r365835_chk'
  tag severity: 'medium'
  tag gid: 'V-207477'
  tag rid: 'SV-207477r854651_rule'
  tag stig_id: 'SRG-OS-000373-VMM-001480'
  tag gtitle: 'SRG-OS-000373'
  tag fix_id: 'F-7734r365836_fix'
  tag 'documentable'
  tag legacy: ['SV-71415', 'V-57155']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
