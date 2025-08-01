control 'SV-207498' do
  title 'The VMM must protect against or limit the effects of Denial of Service (DoS) attacks by ensuring the VMM is implementing rate-limiting measures on impacted network interfaces.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of the VMM to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks, though they may also exacerbate the problem.'
  desc 'check', 'Verify the VMM protects against or limit the effects of Denial of Service (DoS) attacks by ensuring the VMM is implementing rate-limiting measures on impacted network interfaces.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to protect against or limit the effects of Denial of Service (DoS) attacks by ensuring the VMM is implementing rate-limiting measures on impacted network interfaces.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7755r365898_chk'
  tag severity: 'medium'
  tag gid: 'V-207498'
  tag rid: 'SV-207498r854672_rule'
  tag stig_id: 'SRG-OS-000420-VMM-001690'
  tag gtitle: 'SRG-OS-000420'
  tag fix_id: 'F-7755r365899_fix'
  tag 'documentable'
  tag legacy: ['V-57297', 'SV-71557']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
