control 'SV-216992' do
  title 'The Cisco BGP router must be configured to use a unique key for each autonomous system (AS) that it peers with.'
  desc 'If the same keys are used between eBGP neighbors, the chance of a hacker compromising any of the BGP sessions increases. It is possible that a malicious user exists in one autonomous system who would know the key used for the eBGP session. This user would then be able to hijack BGP sessions with other trusted neighbors.'
  desc 'check', 'Review the BGP configuration to determine if it is peering with multiple autonomous systems. Interview the ISSM and router administrator to determine if unique keys are being used. 

router bgp xx
 no synchronization
 bgp log-neighbor-changes
 neighbor x.1.1.9 remote-as yy
 neighbor x.1.1.9 password yyyyyyyy
 neighbor x.2.1.7 remote-as zz
 neighbor x.2.1.7 password zzzzzzzzz

If unique keys are not being used, this is a finding.'
  desc 'fix', 'Configure the router to use unique keys for each AS that it peers with as shown in the example below.

R1(config)#router bgp xx
R1(config-router)#neighbor x.1.1.9 password yyyyyyyy 
R1(config-router)#neighbor x.2.1.7 password zzzzzzzzz'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-18222r287304_chk'
  tag severity: 'medium'
  tag gid: 'V-216992'
  tag rid: 'SV-216992r531085_rule'
  tag stig_id: 'CISC-RT-000480'
  tag gtitle: 'SRG-NET-000230-RTR-000002'
  tag fix_id: 'F-18220r287305_fix'
  tag 'documentable'
  tag legacy: ['V-96593', 'SV-105731']
  tag cci: ['CCI-002205', 'CCI-000366']
  tag nist: ['AC-4 (17)', 'CM-6 b']
end
