control 'SV-242176' do
  title 'The TPS must provide audit record generation capability for detection events based on implementation of policy filters, rules, signatures, and anomaly analysis.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

While auditing and logging are closely related, they are not the same. Logging is recording data about events that take place in a system, while auditing is the use of log records to identify security-relevant information such as system or user accesses. In short, log records are audited to establish an accurate history. Without logging, it would be impossible to establish an audit trail.

The TPS must have the capability to capture and log detected security violations and potential security violations.'
  desc 'check', '1. In the Trend Micro SMS interface, go to the "Admin" tab, and select "Server Properties". 
2. Select the "syslog" tab. If a syslog server is not configured to send the following audit logs, this is a finding:
- Device Audit 
- Device System 
- SMS Audit 
- SMS system'
  desc 'fix', '1. In the Trend Micro SMS interface, go to the "Admin" tab, and select "Server Properties". 
2. Select the "syslog" tab. 
3. Click "New". 
4. Under syslog server type the hostname or IP address of the syslog server. 
5. Click TCP to ensure logging data is queued in the case of disconnection of the syslog server. 
6. Type the port used by the centralized logging server (traditionally it is port 514). 
7. Under log type, select "Device Audit".
8. Under facility click "Log Audit".
9. Click Event timestamp under "Include Timestamp in Header". 
10. Select "include SMS hostname in header".
Repeat this once more, changing the Log Type to include SMS Audit.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45451r710069_chk'
  tag severity: 'medium'
  tag gid: 'V-242176'
  tag rid: 'SV-242176r710071_rule'
  tag stig_id: 'TIPP-IP-000100'
  tag gtitle: 'SRG-NET-000113-IDPS-00013'
  tag fix_id: 'F-45409r710070_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
