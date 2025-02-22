control 'SV-204721' do
  title 'The application server must produce log records containing information to establish what type of events occurred.'
  desc 'Information system logging capability is critical for accurate forensic analysis.  Without being able to establish what type of event occurred, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible. 

Log record content that may be necessary to satisfy the requirement of this control includes time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Application servers must log all relevant log data that pertains to the application server.  Examples of relevant data include, but are not limited to, Java Virtual Machine (JVM) activity, HTTPD/Web server activity, and application server-related system process activity.'
  desc 'check', 'Review the application server log configuration to determine if the application server produces log records showing what type of event occurred.

If the log data does not show the type of event, this is a finding.'
  desc 'fix', 'Configure the application server to include the event type in the log data.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4841r282810_chk'
  tag severity: 'medium'
  tag gid: 'V-204721'
  tag rid: 'SV-204721r879563_rule'
  tag stig_id: 'SRG-APP-000095-AS-000056'
  tag gtitle: 'SRG-APP-000095'
  tag fix_id: 'F-4841r282811_fix'
  tag 'documentable'
  tag legacy: ['V-35159', 'SV-46446']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
