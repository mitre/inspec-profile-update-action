control 'SV-205464' do
  title 'The Mainframe Product must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 

Audit record content that may be necessary to satisfy the requirement of this policy includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Examine installation and configuration settings.

Verify data written to external security manager audit files and/or SMF records contain information that details what type of events occurred. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product audit records written to external security manager audit files and/or SMF records to contain information that details what type of events occurred.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5730r299625_chk'
  tag severity: 'medium'
  tag gid: 'V-205464'
  tag rid: 'SV-205464r395721_rule'
  tag stig_id: 'SRG-APP-000095-MFP-000140'
  tag gtitle: 'SRG-APP-000095'
  tag fix_id: 'F-5730r299626_fix'
  tag 'documentable'
  tag legacy: ['SV-82731', 'V-68241']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
