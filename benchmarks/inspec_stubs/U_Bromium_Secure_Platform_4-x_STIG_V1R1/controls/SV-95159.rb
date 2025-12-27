control 'SV-95159' do
  title 'The Bromium Enterprise Controller (BEC) must generate a log record that can be sent to the central log server, which will alert the system administrator (SA) and Information System Security Officer (ISSO), at a minimum, when it is unable to connect to the SQL database.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without a real-time alert, security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Alerts provide organizations with urgent messages. Real-time alerts provide these messages immediately (i.e., the time from event detection to alert occurs in seconds or less).

Upon loss of connection to the SQL Server, BEC will:
1. Immediately create a number of log entries in "default.log" and "worker.log"; 
2. Refuse connections from the endpoints, which will result in the endpoints automatically storing local events (for future transfer when the SQL connection is restored); and
3. Immediately notify the BEC administrator during logon via the management console interface.'
  desc 'check', 'Ask the site representatives if they have developed and implemented a solution for storing the contents of "default.log" and "worker.log" to receive alerts if SQL Server becomes unavailable. 

The contents of "default.log" and "worker.log" should be sent to a centralized events server. Check that the agent associated with the event server has been installed on the BEC.
 
If the BEC does not generate an immediate log entry that can be sent to the central log server, which will alert the SA and ISSO, at a minimum, when it is unable to connect to the SQL database, this is a finding.'
  desc 'fix', %q(Automatically forward all contents of "default.log" and "worker.log" to the site's central log server in real time. 

Install the file monitoring agent that is provided by the site's centralized events server (e.g., syslog, SIEM) and configure to monitor and forward "default.log" and "worker.log" (example: C:\Program Data\Bromium\BMS\Logs\default.log). Follow the instructions included with the event log server.)
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80127r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80455'
  tag rid: 'SV-95159r1_rule'
  tag stig_id: 'BROM-00-000785'
  tag gtitle: 'SRG-APP-000360'
  tag fix_id: 'F-87261r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
