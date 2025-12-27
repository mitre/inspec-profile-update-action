control 'SV-207340' do
  title 'The VMM must automatically disable local accounts after a 35-day period of account inactivity.'
  desc 'Attackers that are able to exploit an inactive account can potentially obtain and maintain undetected access to an application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. VMMs need to track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be hijacked, leading to a data compromise.

This policy does not apply to either emergency accounts or infrequently used accounts. Infrequently used accounts are local logon administrator accounts used by the system administrator when network or normal logon/access is not available. Emergency accounts are accounts created in response to crisis situations.'
  desc 'check', 'Verify the VMM automatically disables local accounts after a 35-day period of account inactivity.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to automatically disable local accounts after a 35-day period of account inactivity.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7597r365430_chk'
  tag severity: 'medium'
  tag gid: 'V-207340'
  tag rid: 'SV-207340r378484_rule'
  tag stig_id: 'SRG-OS-000003-VMM-000030'
  tag gtitle: 'SRG-OS-000003'
  tag fix_id: 'F-7597r365431_fix'
  tag 'documentable'
  tag legacy: ['SV-71081', 'V-56821']
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
