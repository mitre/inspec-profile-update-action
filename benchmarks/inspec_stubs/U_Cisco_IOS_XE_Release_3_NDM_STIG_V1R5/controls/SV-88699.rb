control 'SV-88699' do
  title 'The Cisco IOS XE router must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the network device does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the passwords could be compromised. 

This requirement does not include emergency administration accounts which are meant for access to the network device in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured to enforce a 60-day maximum password life.

The configuration should look like the example below:

aaa common-criteria policy <Policy Name>
lifetime month 2

If a 60-day maximum password life is not configured, this is a finding.'
  desc 'fix', 'Use the following commands to configure a 60-day maximum password life:

aaa common-criteria policy <Policy Name>
lifetime month 2'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74115r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74025'
  tag rid: 'SV-88699r2_rule'
  tag stig_id: 'CISR-ND-000065'
  tag gtitle: 'SRG-APP-000174-NDM-000261'
  tag fix_id: 'F-80567r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
