control 'SV-203724' do
  title 'The operating system must require users to re-authenticate when changing roles.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to change security roles, it is critical the user re-authenticate.'
  desc 'check', 'Verify the operating system requires users to re-authenticate when changing roles. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to require users to re-authenticate when changing roles.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3849r375179_chk'
  tag severity: 'medium'
  tag gid: 'V-203724'
  tag rid: 'SV-203724r851795_rule'
  tag stig_id: 'SRG-OS-000373-GPOS-00157'
  tag gtitle: 'SRG-OS-000373'
  tag fix_id: 'F-3849r375180_fix'
  tag 'documentable'
  tag legacy: ['V-56831', 'SV-71091']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
