control 'SV-207478' do
  title 'The VMM must require users to re-authenticate when changing authenticators.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When VMMs provide the capability to change user authenticators, it is critical the user re-authenticate.'
  desc 'check', 'Verify the VMM requires users to re-authenticate when changing authenticators.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to require users to re-authenticate when changing authenticators.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7735r365838_chk'
  tag severity: 'medium'
  tag gid: 'V-207478'
  tag rid: 'SV-207478r854652_rule'
  tag stig_id: 'SRG-OS-000373-VMM-001490'
  tag gtitle: 'SRG-OS-000373'
  tag fix_id: 'F-7735r365839_fix'
  tag 'documentable'
  tag legacy: ['V-57157', 'SV-71417']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
