control 'SV-203725' do
  title 'The operating system must require users to re-authenticate when changing authenticators.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to change user authenticators, it is critical the user re-authenticate.'
  desc 'check', 'Verify the operating system requires users to re-authenticate when changing authenticators. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to require users to re-authenticate when changing authenticators.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3850r375182_chk'
  tag severity: 'medium'
  tag gid: 'V-203725'
  tag rid: 'SV-203725r851796_rule'
  tag stig_id: 'SRG-OS-000373-GPOS-00158'
  tag gtitle: 'SRG-OS-000373'
  tag fix_id: 'F-3850r375183_fix'
  tag 'documentable'
  tag legacy: ['SV-71087', 'V-56827']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
