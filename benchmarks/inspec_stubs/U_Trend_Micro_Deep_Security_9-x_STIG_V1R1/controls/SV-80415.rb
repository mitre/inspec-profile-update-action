control 'SV-80415' do
  title 'Trend Deep Security must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised. 

This requirement does not include emergency administration accounts which are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure a 60 day maximum password lifetime restriction is enforced.

Verify the policy value for minimum password length.

If the value for “User password expires” under the Administration >> System Settings >> Security tab is not set to 60 Days, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to enforce a 60 day maximum password lifetime restriction.

Configure the policy value for maximum password lifetime.

Under the Administration >> System Settings >> Security tab, set the value for “User password expires” to 60.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66573r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65925'
  tag rid: 'SV-80415r1_rule'
  tag stig_id: 'TMDS-00-000165'
  tag gtitle: 'SRG-APP-000174'
  tag fix_id: 'F-72001r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
