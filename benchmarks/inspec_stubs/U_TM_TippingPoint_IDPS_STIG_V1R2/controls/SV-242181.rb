control 'SV-242181' do
  title 'The SMS must produce audit records containing information to establish the source of the event, including, at a minimum, originating source address by sending all audit and system logs to a centralized syslog server.'
  desc 'Associating the source of the event with detected events in the logs provides a means of investigating an attack or suspected attack.

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
  tag check_id: 'C-45456r710084_chk'
  tag severity: 'medium'
  tag gid: 'V-242181'
  tag rid: 'SV-242181r710086_rule'
  tag stig_id: 'TIPP-IP-000150'
  tag gtitle: 'SRG-NET-000077-IDPS-00062'
  tag fix_id: 'F-45414r710085_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
