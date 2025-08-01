control 'SV-69611' do
  title 'IDPS components, including sensors, event databases, and management consoles must integrate with a network-wide monitoring capability.'
  desc "An integrated, network-wide intrusion detection capability increases the ability to detect and prevent sophisticated distributed attacks based on access patterns and characteristics of access.

Integration is more than centralized logging and a centralized management console. The enclave's monitoring capability may include multiple sensors, IPS, sensor event databases, behavior-based monitoring devices, application-level content inspection systems, malicious code protection software, scanning tools, audit record monitoring software, and network monitoring software. Some tools may monitor external traffic while others monitor internal traffic at key boundaries. 

These capabilities may be implemented using different devices and therefore can have different security policies and severity-level schema. This is valuable because content filtering, monitoring, and prevention can become a bottleneck on the network if not carefully configured."
  desc 'check', 'Verify the IDPS integrates with a network-wide monitoring capability which includes sensors, event databases, and management consoles.

If the IDPS does not integrate with a network-wide monitoring capability which includes sensors, event databases, and management consoles, this is a finding.'
  desc 'fix', 'Configure the IDPS components, including sensors, event databases, and management consoles to integrate with a network-wide monitoring capability.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55989r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55365'
  tag rid: 'SV-69611r1_rule'
  tag stig_id: 'SRG-NET-000383-IDPS-00208'
  tag gtitle: 'SRG-NET-000383-IDPS-00208'
  tag fix_id: 'F-60231r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002656']
  tag nist: ['SI-4 (1)']
end
