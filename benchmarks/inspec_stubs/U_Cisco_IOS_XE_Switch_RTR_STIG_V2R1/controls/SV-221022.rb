control 'SV-221022' do
  title 'The Cisco BGP switch must be configured to use a unique key for each autonomous system (AS) that it peers with.'
  desc 'If the same keys are used between eBGP neighbors, the chance of a hacker compromising any of the BGP sessions increases. It is possible that a malicious user exists in one autonomous system who would know the key used for the eBGP session. This user would then be able to hijack BGP sessions with other trusted neighbors.'
  desc 'check', 'Review the BGP configuration to determine if it is peering with multiple autonomous systems. Interview the ISSM and switch administrator to determine if unique keys are being used. 

router bgp xx
 no synchronization
 bgp log-neighbor-changes
 neighbor x.1.1.9 remote-as yy
 neighbor x.1.1.9 password yyyyyyyy
 neighbor x.2.1.7 remote-as zz
 neighbor x.2.1.7 password zzzzzzzzz

If unique keys are not being used, this is a finding.'
  desc 'fix', 'Configure the switch to use unique keys for each AS that it peers with as shown in the example below:

SW1(config)#router bgp xx
SW1(config-switch)#neighbor x.1.1.9 password yyyyyyyy 
SW1(config-switch)#neighbor x.2.1.7 password zzzzzzzzz'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22737r408860_chk'
  tag severity: 'medium'
  tag gid: 'V-221022'
  tag rid: 'SV-221022r622190_rule'
  tag stig_id: 'CISC-RT-000480'
  tag gtitle: 'SRG-NET-000230-RTR-000002'
  tag fix_id: 'F-22726r408861_fix'
  tag 'documentable'
  tag legacy: ['SV-110865', 'V-101761']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
