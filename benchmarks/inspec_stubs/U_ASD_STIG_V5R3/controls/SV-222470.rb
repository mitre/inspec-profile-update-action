control 'SV-222470' do
  title 'The application must log destination IP addresses.'
  desc 'The IP addresses of the systems that the application connects to are an important aspect of identifying application network related activity. Recording the IP addresses of the system the application connects to in the application logs provides forensic evidence and aids in investigating and correlating the sources of malicious behavior related to security events. Logging this information can be particularly useful for Service-Oriented Applications where there is application to application connectivity.'
  desc 'check', 'If the application design documentation indicates the application does not initiate connections to remote systems this requirement is not applicable.

Network connections to systems used for support services such as DNS, AD, or LDAP may be stored in the system logs. These connections are applicable.

Identify log source based upon application architecture, design documents and input from application admin.

Review and monitor the application or system logs.

Connect to the application and utilize the application functionality that initiates connections to a destination system.

If the application routinely connects to remote system on a regular basis you may simply allow the application to operate in the background while the logs are observed.

Observe the log activity and determine if the log includes an entry to indicate the IP address of the destination system.

If the IP address of the remote system is not recorded along with the event in the event log, this is a finding.'
  desc 'fix', 'Configure the application to record the destination IP address of the remote system.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24140r493318_chk'
  tag severity: 'medium'
  tag gid: 'V-222470'
  tag rid: 'SV-222470r879563_rule'
  tag stig_id: 'APSC-DV-000950'
  tag gtitle: 'SRG-APP-000095'
  tag fix_id: 'F-24129r493319_fix'
  tag 'documentable'
  tag legacy: ['SV-84045', 'V-69423']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
