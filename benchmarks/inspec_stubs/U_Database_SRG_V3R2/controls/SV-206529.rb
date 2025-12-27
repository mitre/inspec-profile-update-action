control 'SV-206529' do
  title 'The DBMS must produce audit records containing time stamps to establish when the events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing when events occurred, it is impossible to establish, correlate, and investigate the events relating to an incident.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the date and time when events occurred.

Associating the date and time with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly when specific actions were performed. This requires the date and time an audit record is referring to. If date and time information is not recorded and stored with the audit record, the record itself is of very limited use.'
  desc 'check', 'Check DBMS settings and existing audit records to verify information specific to the date and time of the event is being captured and stored with the audit records.

If audit records exist without the date and time of the event, this is a finding.'
  desc 'fix', 'Configure DBMS audit settings to include the date and time of the occurrence of the event as part of the audit record.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6789r291255_chk'
  tag severity: 'medium'
  tag gid: 'V-206529'
  tag rid: 'SV-206529r617447_rule'
  tag stig_id: 'SRG-APP-000096-DB-000040'
  tag gtitle: 'SRG-APP-000096'
  tag fix_id: 'F-6789r291256_fix'
  tag 'documentable'
  tag legacy: ['SV-42706', 'V-32369']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
