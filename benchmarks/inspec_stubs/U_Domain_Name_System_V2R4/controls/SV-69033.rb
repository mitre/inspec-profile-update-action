control 'SV-69033' do
  title 'The DNS server implementation must produce audit records containing information to establish where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident. Associating information about where the event occurred within the application provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured application. In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as application components, modules, session identifiers, filenames, host names, and functionality.'
  desc 'check', 'Review the DNS system configuration to determine if it is configured to produce, capture and store log records which contain information to establish where events have occurred on the system. 

If the logging function is not configured to produce log records with information regarding where the event took place, this is a finding.'
  desc 'fix', 'Configure the DNS server to produce log records that contain information that establishes where events have occurred.

Additionally, configure the audit facility of the DNS system to provide information where events have occurred.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55409r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54787'
  tag rid: 'SV-69033r1_rule'
  tag stig_id: 'SRG-APP-000097-DNS-000008'
  tag gtitle: 'SRG-APP-000097-DNS-000008'
  tag fix_id: 'F-59645r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
