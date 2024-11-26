control 'SV-217000' do
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
  desc 'fix', 'Configure the router to use unique keys for each AS that it peers with as shown in the example below:

R1(config)#router bgp xx
R1(config-router)#neighbor x.1.1.9 password yyyyyyyy 
R1(config-router)#neighbor x.2.1.7 password zzzzzzzzz'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-18230r288162_chk'
  tag severity: 'medium'
  tag gid: 'V-217000'
  tag rid: 'SV-217000r855843_rule'
  tag stig_id: 'CISC-RT-000480'
  tag gtitle: 'SRG-NET-000230-RTR-000002'
  tag fix_id: 'F-18228r288163_fix'
  tag 'documentable'
  tag legacy: ['SV-106083', 'V-96945']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
