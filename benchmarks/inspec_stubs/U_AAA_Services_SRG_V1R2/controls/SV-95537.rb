control 'SV-95537' do
  title 'AAA Services must be configured to automatically disable accounts after a 35-day period of account inactivity.'
  desc 'Attackers that are able to exploit an inactive account can potentially obtain and maintain undetected access to an application. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained. Applications need to track periods of user inactivity and disable accounts after 35 days of inactivity. Such a process greatly reduces the risk that accounts will be hijacked, leading to a data compromise. 

This policy does not apply to either emergency accounts or an infrequently used account (e.g., account of last resort). Infrequently used accounts are local logon administrator accounts used by system administrators when network or normal logon/access is not available. Emergency accounts are administrator accounts created in response to crisis situations.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 

Verify AAA Services are configured to automatically disable accounts after a 35-day period of account inactivity.

If the AAA Services configuration does not automatically disable accounts after a 35-day period of account inactivity, this is a finding.'
  desc 'fix', 'Configure AAA Services to automatically disable accounts after a 35-day period of account inactivity.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80563r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80827'
  tag rid: 'SV-95537r1_rule'
  tag stig_id: 'SRG-APP-000025-AAA-000080'
  tag gtitle: 'SRG-APP-000025-AAA-000080'
  tag fix_id: 'F-87681r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
