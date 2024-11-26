control 'SV-69031' do
  title 'The DNS server implementation must produce audit records containing information to establish what type of events occurred.'
  desc 'Auditing and logging are key components of any security architecture. It is essential for security personnel to know what is being performed on the system, where an event occurred, when an event occurred, and by whom the event was triggered, in order to compile an accurate risk assessment. Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or to simply identify an improperly configured DNS implementation. Without log records that aid in the establishment of what types of events occurred and when those events occurred, there is no traceability for forensic or analytical purposes, and the cause of events is severely hindered.'
  desc 'check', 'Review the DNS system configuration to determine if it is configured to log sufficient information to establish what type of events has occurred on the system. 

If the logging function is not configured to produce log records with information regarding the type of event, this is a finding.'
  desc 'fix', 'Configure the DNS server to log events with enough information to determine what type of event has occurred on the system.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55407r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54785'
  tag rid: 'SV-69031r1_rule'
  tag stig_id: 'SRG-APP-000095-DNS-000006'
  tag gtitle: 'SRG-APP-000095-DNS-000006'
  tag fix_id: 'F-59643r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
