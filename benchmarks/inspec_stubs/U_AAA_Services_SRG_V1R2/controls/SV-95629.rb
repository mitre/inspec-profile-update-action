control 'SV-95629' do
  title 'AAA Services must be configured to enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised. 

This requirement does not include emergency administration accounts that are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.

Where passwords are used, such as temporary or emergency accounts, verify AAA Services are configured to enforce a 60-day maximum password lifetime restriction. Additionally, AAA Services must force password change upon the first logon after the expiration of the 60 days.

If AAA Services are not configured to enforce a 60-day maximum password lifetime restriction, this is a finding.'
  desc 'fix', 'Configure AAA Services to enforce a 60-day maximum password lifetime restriction. Additionally, configure AAA Services to force password change upon the first logon after the expiration of the 60 days. This requirement is not applicable to service account passwords (e.g. shared secrets, pre-shared keys) or the account of last resort.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80657r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80919'
  tag rid: 'SV-95629r1_rule'
  tag stig_id: 'SRG-APP-000174-AAA-000540'
  tag gtitle: 'SRG-APP-000174-AAA-000540'
  tag fix_id: 'F-87775r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
