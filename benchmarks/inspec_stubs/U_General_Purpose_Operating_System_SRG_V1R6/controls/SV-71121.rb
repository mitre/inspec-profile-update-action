control 'SV-71121' do
  title 'The operating system must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'Verify the operating system manages excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57431r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56861'
  tag rid: 'SV-71121r1_rule'
  tag stig_id: 'SRG-OS-000142-GPOS-00071'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-61757r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
