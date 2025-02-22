control 'SV-203723' do
  title 'The operating system must require users to re-authenticate for privilege escalation.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.'
  desc 'check', 'Verify the operating system requires users to re-authenticate for privilege escalation. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to require users to re-authenticate for privilege escalation.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3848r375176_chk'
  tag severity: 'medium'
  tag gid: 'V-203723'
  tag rid: 'SV-203723r379846_rule'
  tag stig_id: 'SRG-OS-000373-GPOS-00156'
  tag gtitle: 'SRG-OS-000373'
  tag fix_id: 'F-3848r375177_fix'
  tag 'documentable'
  tag legacy: ['SV-71097', 'V-56837']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
