control 'SV-233928' do
  title 'The Infoblox DNS server implementation must log the event and notify the system administrator when anomalies in the operation of the signed zone transfers are discovered.'
  desc 'Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes but is not limited to establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights. 

If anomalies are not acted upon, security functions may fail to secure the system. 

The DNS server does not have the capability of shutting down or restarting the information system. The DNS server can be configured to generate audit records when anomalies are discovered, and the OS/NDM can then trigger notification messages to the system administrator based on the presence of those audit records.'
  desc 'check', 'Infoblox systems are capable of providing notifications via remote SYSLOG, SNMP, and SMTP. 

1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration. 
2. Select the "Monitoring" tab. 
3. Verify that "Log to External Syslog Servers" is enabled and an External Syslog Server is configured. 
4. Click "Cancel" to exit the "Properties" screen.  
5. Navigate to DNS >> DNS Management and select Grid or System DNS Properties if using a stand-alone configuration.  
6. Toggle Advanced Mode and select the "Logging" tab. Validate that the "dnsssec" SYSLOG category is enabled. 
7. When complete, click "Cancel" to exit the "Properties" screen.  

If DNSSEC is not configured to send external notifications to a valid external SYSLOG server, this is a finding.'
  desc 'fix', '1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration.  
2. Select the "Monitoring" tab.  
3. Enable "Log to External Syslog Servers" using the check box. 
4. Configure an "External Syslog Server".
5. Click "Save & Close" to save the changes and exit the "Properties" screen. 
6. Navigate to DNS >> DNS Management and select Grid or System DNS Properties if using a stand-alone configuration.  
7. Toggle Advanced Mode and select the "Logging" tab.  
8. Enable the "dnsssec" SYSLOG category. 
9. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
10. Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37113r611304_chk'
  tag severity: 'medium'
  tag gid: 'V-233928'
  tag rid: 'SV-233928r621666_rule'
  tag stig_id: 'IDNS-8X-800002'
  tag gtitle: 'SRG-APP-000474-DNS-000073'
  tag fix_id: 'F-37078r611305_fix'
  tag 'documentable'
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
