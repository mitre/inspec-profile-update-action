control 'SV-203658' do
  title 'The operating system must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'Verify the operating system manages excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3783r557219_chk'
  tag severity: 'medium'
  tag gid: 'V-203658'
  tag rid: 'SV-203658r557221_rule'
  tag stig_id: 'SRG-OS-000142-GPOS-00071'
  tag gtitle: 'SRG-OS-000142'
  tag fix_id: 'F-3783r557220_fix'
  tag 'documentable'
  tag legacy: ['V-56861', 'SV-71121']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
