control 'SV-69037' do
  title 'The DNS server implementation must produce audit records that contain information to establish the outcome of the events.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment about whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the information system after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Review the DNS server configuration to determine if it is configured to produce, capture, and store log records which contain information about success and failure of events on the system. 

If the logging function is not configured to produce log records with information regarding success and failure of events, this is a finding.'
  desc 'fix', 'Configure the DNS server to produce log records that contain information about success and failure of events on the system.

Additionally, configure the audit facility of the DNS system to provide information to establish the success or failure of the event.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55413r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54791'
  tag rid: 'SV-69037r1_rule'
  tag stig_id: 'SRG-APP-000099-DNS-000010'
  tag gtitle: 'SRG-APP-000099-DNS-000010'
  tag fix_id: 'F-59649r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
