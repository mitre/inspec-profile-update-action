control 'SV-205504' do
  title 'The Mainframe Product must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised. 

This requirement does not include emergency administration accounts that are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'If the Mainframe Product employs an external security manager (ESM) for all account management functions, this is not applicable.

Examine user account management configurations. 

If the Mainframe Product account management configuration does not enforce a 60-day maximum password lifetime restriction, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to enforce a 60-day maximum password lifetime restriction.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5770r299745_chk'
  tag severity: 'medium'
  tag gid: 'V-205504'
  tag rid: 'SV-205504r397591_rule'
  tag stig_id: 'SRG-APP-000174-MFP-000236'
  tag gtitle: 'SRG-APP-000174'
  tag fix_id: 'F-5770r299746_fix'
  tag 'documentable'
  tag legacy: ['SV-82881', 'V-68391']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
