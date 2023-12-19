control 'SV-69471' do
  title 'The DNS server implementation must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident. 

Associating event types with detected events in the application and audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured application. In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know when events occurred (date and time).'
  desc 'check', 'Review the DNS system configuration to determine if it is configured to produce, capture, and store log records that contain information to establish when (date and time) events have occurred on the system. 

If the logging function is not configured to produce log records with information regarding when the event took place, this is a finding.'
  desc 'fix', 'Configure the DNS server to produce log records that contain information that establishes when (date and time) events have occurred on the system.

Additionally, configure the audit facility of the DNS system to provide information when events have occurred.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55845r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55225'
  tag rid: 'SV-69471r1_rule'
  tag stig_id: 'SRG-APP-000096-DNS-000007'
  tag gtitle: 'SRG-APP-000096-DNS-000007'
  tag fix_id: 'F-60089r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
