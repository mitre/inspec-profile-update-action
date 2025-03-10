control 'SV-207345' do
  title 'The VMM must limit the number of concurrent sessions to ten for all accounts and/or account types.'
  desc 'VMM management includes the ability to control the number of users and user sessions that utilize the VMM. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for VMM accounts and does not address concurrent sessions by single users via multiple VMM accounts. If the concurrent-session limitation of ten is insufficient to support operational requirements, it may be set to a higher value, but it must not be unlimited.'
  desc 'check', 'Verify the VMM limits the number of concurrent sessions to ten for all accounts and/or account types.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to limit the number of concurrent sessions to ten for all accounts and/or account types.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7602r365445_chk'
  tag severity: 'medium'
  tag gid: 'V-207345'
  tag rid: 'SV-207345r378532_rule'
  tag stig_id: 'SRG-OS-000027-VMM-000080'
  tag gtitle: 'SRG-OS-000027'
  tag fix_id: 'F-7602r365446_fix'
  tag 'documentable'
  tag legacy: ['SV-71115', 'V-56855']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
