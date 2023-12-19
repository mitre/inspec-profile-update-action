control 'SV-95571' do
  title 'AAA Services configuration audit records must identify where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know where events occurred, such as application components, modules, session identifiers, filenames, host names, and functionality. 

Associating information about where the event occurred within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Verify AAA Services configuration audit records identify where the events occurred.

If AAA Services configuration audit records do not identify where the events occurred, this is a finding.'
  desc 'fix', 'Configure AAA Services audit records to identify where the events occurred.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80597r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80861'
  tag rid: 'SV-95571r1_rule'
  tag stig_id: 'SRG-APP-000097-AAA-000240'
  tag gtitle: 'SRG-APP-000097-AAA-000240'
  tag fix_id: 'F-87715r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
