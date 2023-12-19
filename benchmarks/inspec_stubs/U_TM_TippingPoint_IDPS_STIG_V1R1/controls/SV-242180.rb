control 'SV-242180' do
  title 'The SMS must produce audit records containing information to establish where the event was detected, including, at a minimum, network segment, destination address, and TPS component which detected the event by sending all audit and system logs to a centralized syslog server.'
  desc 'Associating where the event was detected with the event log entries provides a means of investigating an attack or identifying an improperly configured IDPS. This information can be used to determine what systems may have been affected.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.'
  desc 'check', '1. In the Trend Micro SMS interface, go to the "Admin" tab, and select "Server Properties". 
2. Select the "syslog" tab. If a syslog server is not configured to send the following audit logs, this is a finding:
- Device Audit 
- Device System
- SMS Audit 
- SMS system'
  desc 'fix', '1. In the Trend Micro SMS interface, go to the "Admin" tab, and select "Server Properties". 
2. Select the "syslog" tab. Click "New".
3. Under syslog server type the hostname or IP address of the syslog server.
4. Click TCP to ensure logging data is queued in the case of disconnection of the syslog server. 
5. Type the port used by the centralized logging server (traditionally it is port 514).
6. Under log type, select Device Audit.
7. Under facility click "Log Audit". 
8. Click Event timestamp under "Include Timestamp in Header".
9. Select "include SMS hostname in header". 
Repeat this three more times changing the Log Type to include Device System, SMS Audit, and SMS System.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45455r710081_chk'
  tag severity: 'medium'
  tag gid: 'V-242180'
  tag rid: 'SV-242180r710347_rule'
  tag stig_id: 'TIPP-IP-000140'
  tag gtitle: 'SRG-NET-000076-IDPS-00061'
  tag fix_id: 'F-45413r710082_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
