control 'SV-242200' do
  title 'SMS and TPS components, including sensors, event databases, and management consoles must integrate with a network-wide monitoring capability.'
  desc "An integrated, network-wide intrusion detection capability increases the ability to detect and prevent sophisticated distributed attacks based on access patterns and characteristics of access.

Integration is more than centralized logging and a centralized management console. The enclave's monitoring capability may include multiple sensors, IPS, sensor event databases, behavior-based monitoring devices, application-level content inspection systems, malicious code protection software, scanning tools, audit record monitoring software, and network monitoring software. Some tools may monitor external traffic while others monitor internal traffic at key boundaries. 

These capabilities may be implemented using different devices and therefore can have different security policies and severity-level schema. This is valuable because content filtering, monitoring, and prevention can become a bottleneck on the network if not carefully configured."
  desc 'check', '1. In the Trend Micro SMS interface, go to the "Admin" tab, and select "Server Properties". 
2. Select the "syslog" tab. 

If a syslog server is not configured to send the following audit logs, this is a finding:

- Device Audit
- Device System 
- SMS Audit
- SMS system'
  desc 'fix', '1. In the Trend Micro SMS interface, go to the "Admin" tab, and select "Server Properties". 
2. Select the "syslog" tab. Click "New".
3. Under syslog server type the hostname or IP address of the syslog server. 
4. Click TCP to ensure logging data is queued in the case of disconnection of the syslog server. 
5. Type the port used by the centralized logging server (traditionally it is port 514).
6. Under log type, select "Device Audit". 
7. Under facility click "Log Audit". 
8. Click Event timestamp under "Include Timestamp in Header".
9. Select "include SMS hostname in header".
Repeat this three more times changing the Log Type to include Device System, SMS Audit, and SMS System.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45475r710141_chk'
  tag severity: 'medium'
  tag gid: 'V-242200'
  tag rid: 'SV-242200r710143_rule'
  tag stig_id: 'TIPP-IP-000370'
  tag gtitle: 'SRG-NET-000383-IDPS-00208'
  tag fix_id: 'F-45433r710142_fix'
  tag 'documentable'
  tag cci: ['CCI-002656']
  tag nist: ['SI-4 (1)']
end
