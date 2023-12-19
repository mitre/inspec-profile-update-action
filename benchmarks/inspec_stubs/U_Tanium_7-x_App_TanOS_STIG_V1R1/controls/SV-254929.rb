control 'SV-254929' do
  title 'Tanium must notify system administrator and ISSO of account enabling actions.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Sending notification of account enabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.

To detect and respond to events that affect user accessibility and application processing, applications must notify the appropriate individuals so they can investigate the event.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to offload those access control functions and focus on core application features and functionality.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect". 

4. Review the configured sources.

If no sources exist to send audit logs from the Tanium SQL Server to a SIEM tool or email destination, this is a finding.

1. Work with the SIEM administrator to determine if an alert is configured when account-enabling actions are performed.

If there is no alert configured, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect". 

4. Configure sources to send audit logs from the Tanium SQL Server to a SIEM tool or email destination.

5. Work with email administrator to configure email destination.

6. Work with the SIEM administrator to configure an alert when account-enabling actions are performed.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58542r867685_chk'
  tag severity: 'medium'
  tag gid: 'V-254929'
  tag rid: 'SV-254929r867687_rule'
  tag stig_id: 'TANS-AP-000780'
  tag gtitle: 'SRG-APP-000320'
  tag fix_id: 'F-58486r867686_fix'
  tag 'documentable'
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
