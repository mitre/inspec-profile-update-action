control 'SV-79493' do
  title 'The DBN-6300 must generate log events for detection events based on anomaly analysis.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 
 
While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail. 
 
The IDPS must have the capability to capture and log detected security violations and potential security violations.'
  desc 'check', 'Verify the DBN-6300 is connected to the syslog server. 
 
Navigate to Settings >> Advanced >> Syslog. 
 
Verify that the syslog services are set to "on", the syslog server information is valid, and the syslog server has connected. 
 
If the DBN-6300 is not connected to the syslog server, or if the syslog server is connected when an event/alert occurs and this event does not appear in the syslog server, this is a finding.'
  desc 'fix', 'Configure the DBN-6300 to be connected to the syslog server. 
 
Navigate to Settings >> Advanced >> Syslog. 
 
Enter the syslog connection information (port and IP address) and push the "enabled" button for both "TCP" and "enable". 
 
Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 IDPS'
  tag check_id: 'C-65661r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65003'
  tag rid: 'SV-79493r1_rule'
  tag stig_id: 'DBNW-IP-000012'
  tag gtitle: 'SRG-NET-000113-IDPS-00013'
  tag fix_id: 'F-70943r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
