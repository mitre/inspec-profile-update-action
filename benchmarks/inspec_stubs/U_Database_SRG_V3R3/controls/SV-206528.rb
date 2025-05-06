control 'SV-206528' do
  title 'The DBMS must produce audit records containing sufficient information to establish what type of events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

Database software is capable of a range of actions on data stored within the database. It is important, for accurate forensic analysis, to know exactly what actions were performed. This requires specific information regarding the event type an audit record is referring to. If event type information is not recorded and stored with the audit record, the record itself is of very limited use.'
  desc 'check', 'Check DBMS settings and existing audit records to verify information specific to the audit event type is being captured and stored with the audit records.

If audit records exist without information regarding what type of event occurred, this is a finding.'
  desc 'fix', 'Configure DBMS audit settings to include event type as part of the audit record.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6788r291252_chk'
  tag severity: 'medium'
  tag gid: 'V-206528'
  tag rid: 'SV-206528r617447_rule'
  tag stig_id: 'SRG-APP-000095-DB-000039'
  tag gtitle: 'SRG-APP-000095'
  tag fix_id: 'F-6788r291253_fix'
  tag 'documentable'
  tag legacy: ['SV-42705', 'V-32368']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
