control 'SV-233895' do
  title 'The Infoblox system must notify the system administrator when a component failure is detected.'
  desc 'Predictable failure prevention requires organizational planning to address system failure issues. If components key to maintaining systems security fail to function, the system could continue operating in an insecure state. The organization must be prepared and the application must support requirements that specify if the application must alarm for such conditions and/or automatically shut down the application or the system.

This can include conducting a graceful application shutdown to avoid losing information. Automatic or manual transfer of components from standby to active mode can occur, for example, upon detection of component failures.'
  desc 'check', 'Infoblox systems are capable of providing notifications via remote SYSLOG, SNMP, and SMTP.  

1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration. 
2. Select the "Monitoring" tab.  
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
  tag check_id: 'C-37080r611205_chk'
  tag severity: 'medium'
  tag gid: 'V-233895'
  tag rid: 'SV-233895r621666_rule'
  tag stig_id: 'IDNS-8X-400037'
  tag gtitle: 'SRG-APP-000268-DNS-000039'
  tag fix_id: 'F-37045r611206_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001328']
  tag nist: ['CM-6 b', 'SI-13 (4) (b)']
end
