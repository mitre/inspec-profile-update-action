control 'SV-69035' do
  title 'The DNS server implementation must produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack. Associating information about the source of the event within the application provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured application. 

In addition to logging where events occur within the application, the application must also produce audit records that identify the application itself as the source of the event. In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event, particularly in the case of centralized logging. In the case of centralized logging, the source would be the application name accompanied by the host or client name.'
  desc 'check', 'Review the DNS server configuration to determine if the source of the events is a configurable option within the audit/logging utility and if it is being captured and stored. 

If the DNS is not configured to capture and store the source of an event, this is a finding.'
  desc 'fix', 'Configure the DNS server to produce log records which indicate the source of the events.

Additionally, configure the audit facility of the DNS system to provide information to establish the source of events.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55411r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54789'
  tag rid: 'SV-69035r1_rule'
  tag stig_id: 'SRG-APP-000098-DNS-000009'
  tag gtitle: 'SRG-APP-000098-DNS-000009'
  tag fix_id: 'F-59647r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
