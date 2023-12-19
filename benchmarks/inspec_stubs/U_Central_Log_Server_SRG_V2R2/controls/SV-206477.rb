control 'SV-206477' do
  title 'The Central Log Server must be configured to enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the application does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the system and/or application passwords could be compromised. 

This requirement does not include emergency administration accounts that are meant for access to the application in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to enforce a 60-day maximum password lifetime restriction.

If the Central Log Server is not configured to enforce a 60-day maximum password lifetime restriction, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to enforce a 60-day maximum password lifetime restriction.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6737r285675_chk'
  tag severity: 'low'
  tag gid: 'V-206477'
  tag rid: 'SV-206477r397591_rule'
  tag stig_id: 'SRG-APP-000174-AU-002570'
  tag gtitle: 'SRG-APP-000174'
  tag fix_id: 'F-6737r285676_fix'
  tag 'documentable'
  tag legacy: ['SV-96073', 'V-81359']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
