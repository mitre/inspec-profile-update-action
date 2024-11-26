control 'SV-242187' do
  title 'The SMS and TPS must provide log information in a format that can be extracted and used by centralized analysis tools.'
  desc 'Centralized review and analysis of log records from multiple SMS and TPS components gives the organization the capability to better detect distributed attacks and provides increased data points for behavior analysis techniques. These techniques are invaluable in monitoring for indicators of complex attack patterns.'
  desc 'check', '1. In the Trend Micro SMS interface, go to the "Admin" tab, and select "Server Properties".
2. Select the "syslog" tab. If a syslog server is not configured to send the following audit logs, this is a finding:
- Device System 
- SMS system'
  desc 'fix', '1. In the Trend Micro SMS interface, go to the "Admin" tab, and select "Server Properties". 
2. Select the "syslog" tab. 
3. Click "New".
4. Under syslog server type the hostname or IP address of the syslog server.
5. Click TCP to ensure logging data is queued in the case of disconnection of the syslog server. 
6. Type the port used by the centralized logging server (traditionally it is port 514). 
7. Under log type, select "Device System". 
8. Under facility click "Log System". 
9. Click Event timestamp under "Include Timestamp in Header". 
10. Select "Include SMS hostname in header".
Repeat this one more time changing the Log Type to include SMS System.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45462r710102_chk'
  tag severity: 'medium'
  tag gid: 'V-242187'
  tag rid: 'SV-242187r710104_rule'
  tag stig_id: 'TIPP-IP-000210'
  tag gtitle: 'SRG-NET-000091-IDPS-00193'
  tag fix_id: 'F-45420r710103_fix'
  tag 'documentable'
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
