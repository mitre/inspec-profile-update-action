control 'SV-206530' do
  title 'The DBMS must produce audit records containing sufficient information to establish where the events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as application components, modules, session identifiers, filenames, host names, and functionality. 

Associating information about where the event occurred within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Check DBMS settings and existing audit records to verify information specific to where the event occurred is being captured and stored with the audit records.

If audit records exist without information regarding where the event occurred, this is a finding.'
  desc 'fix', 'Configure DBMS audit settings to include where the event occurred as part of the audit record.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6790r291258_chk'
  tag severity: 'medium'
  tag gid: 'V-206530'
  tag rid: 'SV-206530r617447_rule'
  tag stig_id: 'SRG-APP-000097-DB-000041'
  tag gtitle: 'SRG-APP-000097'
  tag fix_id: 'F-6790r291259_fix'
  tag 'documentable'
  tag legacy: ['SV-42707', 'V-32370']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
