control 'SV-90887' do
  title 'CounterACT must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals.

One method of minimizing this risk is to use complex passwords and periodically change them. If the network device does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the passwords could be compromised.

This requirement does not include root account or the account of last resort which are meant for access to the network device in case of failure.'
  desc 'check', 'Determine if CounterACT enforces a 60-day maximum password lifetime. This requirement may be verified by demonstration or configuration review. This requirement does not include root account or the account of last resort.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Verify the "password expires after" radio button is selected and configured to 60 days.

If CounterACT does not enforce a 60-day maximum password lifetime, this is a finding.'
  desc 'fix', 'Configure CounterACT to enforce a 60-day maximum password lifetime.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Verify the "password expires after" radio button is selected and configured to 60 days.

This requirement does not include root account or the account of last resort.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75885r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76199'
  tag rid: 'SV-90887r1_rule'
  tag stig_id: 'CACT-NM-000034'
  tag gtitle: 'SRG-APP-000174-NDM-000261'
  tag fix_id: 'F-82837r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
