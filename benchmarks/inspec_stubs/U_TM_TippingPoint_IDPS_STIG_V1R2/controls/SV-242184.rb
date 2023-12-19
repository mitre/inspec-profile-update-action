control 'SV-242184' do
  title 'The TPS and SMS must off-load log records to a centralized log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Off-loading ensures audit information does not get overwritten if the limited audit storage capacity is reached and also protects the audit record in case the system/component being audited is compromised.

This also prevents the log records from being lost if the logs stored locally are accidentally or intentionally deleted, altered, or corrupted.'
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
10. Select "Include SMS hostname in header". 
Repeat this three more times changing the Log Type to include Device System, SMS Audit, and SMS System.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45459r710093_chk'
  tag severity: 'medium'
  tag gid: 'V-242184'
  tag rid: 'SV-242184r710095_rule'
  tag stig_id: 'TIPP-IP-000180'
  tag gtitle: 'SRG-NET-000334-IDPS-00191'
  tag fix_id: 'F-45417r710094_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
