control 'SV-207476' do
  title 'The VMM must require users to re-authenticate for privilege escalation.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When VMMs provide the capability to escalate a functional capability, it is critical the user re-authenticate.'
  desc 'check', 'Verify the VMM requires users to re-authenticate for privilege escalation.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to require users to re-authenticate for privilege escalation.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7733r365832_chk'
  tag severity: 'medium'
  tag gid: 'V-207476'
  tag rid: 'SV-207476r854650_rule'
  tag stig_id: 'SRG-OS-000373-VMM-001470'
  tag gtitle: 'SRG-OS-000373'
  tag fix_id: 'F-7733r365833_fix'
  tag 'documentable'
  tag legacy: ['SV-71413', 'V-57153']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
