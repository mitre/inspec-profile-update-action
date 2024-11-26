control 'SV-233927' do
  title 'The Infoblox system must notify the ISSO and ISSM in the event of failed security verification tests.'
  desc 'Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes but is not limited to establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. If personnel are not notified of failed security verification tests, they will not be able to take corrective action, and the unsecure condition(s) will remain. Notifications provided by information systems include messages to local computer consoles and/or hardware indications, such as lights.

The Infoblox system must be configured to generate audit records whenever a self-test fails.'
  desc 'check', 'Infoblox systems are capable of providing notifications via remote SYSLOG, SNMP, and SMTP. 

1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration. 
2. Select the Monitoring tab.  
3. Verify that "Log to External Syslog Servers" is enabled and an External Syslog Server is configured. 
4. When complete, click "Cancel" to exit the "Properties" screen.  

If no external notifications are enabled, this is a finding.'
  desc 'fix', '1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration. 
2. Select the Monitoring tab. 
3. Enable "Log to External Syslog Servers" using the check box. 
4. Configure an "External Syslog Server".  
5. When complete, click "Save & Close" to save the changes and exit the "Properties" screen.  
6. Perform a service restart if necessary. 
7. Review the SYSLOG data on the remote SYSLOG server to validate operation.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37112r611301_chk'
  tag severity: 'medium'
  tag gid: 'V-233927'
  tag rid: 'SV-233927r621666_rule'
  tag stig_id: 'IDNS-8X-800001'
  tag gtitle: 'SRG-APP-000275-DNS-000040'
  tag fix_id: 'F-37077r611302_fix'
  tag 'documentable'
  tag cci: ['CCI-001294']
  tag nist: ['SI-6 c']
end
