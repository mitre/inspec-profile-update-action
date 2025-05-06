control 'SV-251261' do
  title 'The Workspace ONE UEM local accounts must be configured with password maximum lifetime of 60 days.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals.

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised.

This requirement does not include emergency administration accounts which are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.

SFR ID: FMT_SMF.1(2)b. / IA-5 (1) (d)'
  desc 'check', 'Verify WS1 UEM is configured to have a local account password lifetime of 60 days for the emergency local account.

1. Log in to the WS1UEM console.
2. Go to Settings >> Admin >> Console Security >> Passwords.
3. Verify "Password Expiration Period (days)" is set to 60.

If WS1 UEM is not configured to have a local account password lifetime of 60 days, this is a finding.'
  desc 'fix', 'Configure WS1 UEM to have a local account password lifetime of 60 days for the emergency local account.

1. Log in to the WS1UEM console.
2. Go to Settings >> Admin >> Console Security >> Passwords.
3. Configure "Password Expiration Period (days)" to 60.'
  impact 0.7
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-54696r805084_chk'
  tag severity: 'high'
  tag gid: 'V-251261'
  tag rid: 'SV-251261r805090_rule'
  tag stig_id: 'VMW1-00-200130'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-54650r805085_fix'
  tag 'documentable'
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
