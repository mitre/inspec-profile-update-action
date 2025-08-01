control 'SV-68911' do
  title 'The ALG providing content filtering must be configured to integrate with a system-wide intrusion detection system.'
  desc 'Without coordinated reporting between separate devices, it is not possible to identify the true scale and possible target of an attack.

Integration of the ALG with a system-wide intrusion detection system supports continuous monitoring and incident response programs. This requirement applies to monitoring at internal boundaries using TLS gateways, web content filters, email gateways, and other types of ALGs.

ALGs can work as part of the network monitoring capabilities to off-load inspection functions from the external boundary IDPS by performing more granular content inspection of protocols at the upper layers of the OSI reference model.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG integrates with a system-wide intrusion detection system.

If the ALG does not integrate with a system-wide intrusion detection system, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to integrate with a system-wide intrusion detection system.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55285r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54665'
  tag rid: 'SV-68911r1_rule'
  tag stig_id: 'SRG-NET-000383-ALG-000135'
  tag gtitle: 'SRG-NET-000383-ALG-000135'
  tag fix_id: 'F-59521r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002656']
  tag nist: ['SI-4 (1)']
end
