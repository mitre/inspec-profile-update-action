control 'SV-95473' do
  title 'The SDN controller must be configured to produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know where (e.g., interface, node, source IP, etc.) events occurred. Associating information about where the event occurred within the network provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network element.'
  desc 'check', 'Review the SDN controller configuration to determine if the audit records will note where (e.g., service, interface, node, link, etc.) the event that is being logged occurred. 

If the SDN controller is not configured to produce audit records containing information to establish where (e.g., service, interface, node, link, etc.) the events occurred, this is a finding.'
  desc 'fix', 'Configure the SDN controller to include where (e.g., service, interface, node, link, etc.) the event occurred in the log records.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80499r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80763'
  tag rid: 'SV-95473r1_rule'
  tag stig_id: 'SRG-NET-000076-SDN-000130'
  tag gtitle: 'SRG-NET-000076'
  tag fix_id: 'F-87617r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
