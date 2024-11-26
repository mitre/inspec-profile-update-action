control 'SV-207404' do
  title 'The VMM must manage excess capacity, bandwidth, or other redundancy to limit the effects of information-flooding types of Denial of Service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'Verify the VMM manages excess capacity, bandwidth, or other redundancy to limit the effects of information-flooding types of Denial of Service (DoS) attacks.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to manage excess capacity, bandwidth, or other redundancy to limit the effects of information-flooding types of Denial of Service (DoS) attacks.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7661r365622_chk'
  tag severity: 'medium'
  tag gid: 'V-207404'
  tag rid: 'SV-207404r378988_rule'
  tag stig_id: 'SRG-OS-000142-VMM-000690'
  tag gtitle: 'SRG-OS-000142'
  tag fix_id: 'F-7661r365623_fix'
  tag 'documentable'
  tag legacy: ['V-57009', 'SV-71269']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
