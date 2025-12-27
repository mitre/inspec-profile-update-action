control 'SV-214180' do
  title 'The Infoblox system must be configured to activate a notification to the system administrator when a component failure is detected.'
  desc 'Predictable failure prevention requires organizational planning to address system failure issues. If components key to maintaining systems security fail to function, the system could continue operating in an insecure state. The organization must be prepared and the application must support requirements that specify if the application must alarm for such conditions and/or automatically shut down the application or the system. 

This can include conducting a graceful application shutdown to avoid losing information. Automatic or manual transfer of components from standby to active mode can occur, for example, upon detection of component failures.

If a component such as the DNSSEC or TSIG/SIG(0) signing capabilities were to fail, the DNS server should shut itself down to prevent continued execution without the necessary security components in place. Transactions such as zone transfers would not be able to work correctly anyway in this state.'
  desc 'check', 'Infoblox systems are capable of providing notifications via remote SYSLOG, SNMP, and SMTP.

Navigate to the "Grid" tab and select "Grid Properties", toggle Advanced Mode, and review "Monitoring", "SNMP", "SNMP Threshold", "Email", and "Notifications" tabs.
When complete, click "Cancel" to exit the "Properties" screen.

If no external notifications are enabled, this is a finding.'
  desc 'fix', 'Navigate to "Grid" tab and edit "Grid Properties", toggle Advanced Mode, and review "Monitoring", "SNMP", "SNMP Threshold", "Email" and "Notifications" tab.

Configure remote SYSLOG, Email, or SNMP notifications.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15395r295803_chk'
  tag severity: 'medium'
  tag gid: 'V-214180'
  tag rid: 'SV-214180r612370_rule'
  tag stig_id: 'IDNS-7X-000370'
  tag gtitle: 'SRG-APP-000268-DNS-000039'
  tag fix_id: 'F-15393r295804_fix'
  tag 'documentable'
  tag legacy: ['SV-83045', 'V-68555']
  tag cci: ['CCI-001328', 'CCI-000366']
  tag nist: ['SI-13 (4) (b)', 'CM-6 b']
end
