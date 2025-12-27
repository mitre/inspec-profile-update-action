control 'SV-70997' do
  title 'The operating system must protect against or limit the effects of Denial of Service (DoS) attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of the operating system to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Verify the operating system protects against or limits the effects of Denial of Service (DoS) attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to protect against or limit the effects of Denial of Service (DoS) attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57307r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56737'
  tag rid: 'SV-70997r1_rule'
  tag stig_id: 'SRG-OS-000420-GPOS-00186'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-61633r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
